import type { JWK } from "jose";
import type { HttpClient } from "../../interfaces";
import type { DataIntegrityProof, Vcdm2Credential } from "../../schemas/Vcdm2CredentialSchema";
import { canonicalizeJcs } from "./jcs";
import { multibaseDecode } from "./multibase";
import { createDocumentLoader } from "./documentLoader";

/**
 * Verification of a W3C Data Integrity proof (VC-DI), covering the
 * cryptosuites our issuers actually emit.
 *
 * `ecdsa-sd-2023` (selective disclosure) is deliberately *not* supported: it
 * needs derived-proof handling well beyond a signature check, and silently
 * treating it as a plain signature would report an unverified credential as
 * verified.
 */

/**
 * Message of a thrown value. Everything that throws on these paths is an
 * Error, so the String() arm is unreachable defence rather than dead weight.
 */
function errorMessage(err: unknown): string {
	/* v8 ignore next -- non-Error throwables are not produced on these paths */
	return err instanceof Error ? err.message : String(err);
}

export type DataIntegrityFailure =
	| { kind: "unsupported-cryptosuite"; cryptosuite: string }
	| { kind: "canonicalization-failed"; message: string }
	| { kind: "context-unresolvable"; message: string }
	| { kind: "invalid-proof"; message: string }
	| { kind: "invalid-signature" };

export type DataIntegrityResult =
	| { success: true }
	| { success: false; failure: DataIntegrityFailure };

type Canonicalization = "rdfc" | "jcs";
type KeyFamily = "ecdsa" | "eddsa";

type Suite = {
	canonicalization: Canonicalization;
	keyFamily: KeyFamily;
};

const SUITES: Record<string, Suite> = {
	"ecdsa-rdfc-2019": { canonicalization: "rdfc", keyFamily: "ecdsa" },
	"ecdsa-jcs-2019": { canonicalization: "jcs", keyFamily: "ecdsa" },
	"eddsa-rdfc-2022": { canonicalization: "rdfc", keyFamily: "eddsa" },
	"eddsa-jcs-2022": { canonicalization: "jcs", keyFamily: "eddsa" },
};

/**
 * Legacy proof types that name their suite in `type` rather than in a
 * separate `cryptosuite` member.
 */
const LEGACY_PROOF_TYPES: Record<string, string> = {
	Ed25519Signature2020: "eddsa-rdfc-2022",
};

export function resolveCryptosuite(proof: DataIntegrityProof): string | undefined {
	if (typeof proof.cryptosuite === "string" && proof.cryptosuite.length > 0) {
		return proof.cryptosuite;
	}
	return LEGACY_PROOF_TYPES[proof.type];
}

/**
 * Hash used for both the document and the proof configuration.
 *
 * The ECDSA suites tie the digest to the curve (P-256/SHA-256,
 * P-384/SHA-384); the EdDSA suites always use SHA-256.
 */
function digestAlgorithmFor(suite: Suite, publicKey: JWK): "SHA-256" | "SHA-384" {
	if (suite.keyFamily === "ecdsa" && publicKey.crv === "P-384") return "SHA-384";
	return "SHA-256";
}

async function canonicalize(
	document: Record<string, unknown>,
	suite: Suite,
	httpClient: HttpClient,
): Promise<string> {
	if (suite.canonicalization === "jcs") {
		return canonicalizeJcs(document);
	}

	// Loaded lazily: jsonld is a heavy dependency and only the *-rdfc-*
	// suites need it, so it stays out of the bundle's critical path.
	const jsonld = (await import("jsonld")).default as any;

	const options = {
		format: "application/n-quads",
		safe: true,
		documentLoader: createDocumentLoader({ httpClient }),
	};

	// "RDFC-1.0" and "URDNA2015" name the same algorithm; which one is
	// accepted depends on the jsonld major version, so try the current name
	// and fall back to the historical one.
	try {
		return await jsonld.canonize(document, { ...options, algorithm: "RDFC-1.0" });
	} catch (err) {
		const message = errorMessage(err);
		if (!/canonicalization algorithm/i.test(message)) throw err;
		return jsonld.canonize(document, { ...options, algorithm: "URDNA2015" });
	}
}

async function sha(subtle: SubtleCrypto, algorithm: "SHA-256" | "SHA-384", data: Uint8Array): Promise<Uint8Array> {
	// Copy into a fresh buffer so a subarray view can't hand SubtleCrypto more
	// bytes than intended.
	const digest = await subtle.digest(algorithm, new Uint8Array(data).buffer as ArrayBuffer);
	return new Uint8Array(digest);
}

async function verifySignature(args: {
	subtle: SubtleCrypto;
	suite: Suite;
	publicKey: JWK;
	digestAlgorithm: "SHA-256" | "SHA-384";
	signature: Uint8Array;
	data: Uint8Array;
}): Promise<boolean> {
	const { subtle, suite, publicKey, digestAlgorithm, signature, data } = args;

	const importParams: EcKeyImportParams | Algorithm = suite.keyFamily === "ecdsa"
		? { name: "ECDSA", namedCurve: (publicKey.crv as string) ?? "P-256" }
		: { name: "Ed25519" };

	const key = await subtle.importKey(
		"jwk",
		publicKey as JsonWebKey,
		importParams as AlgorithmIdentifier,
		false,
		["verify"],
	);

	const verifyParams: EcdsaParams | Algorithm = suite.keyFamily === "ecdsa"
		? { name: "ECDSA", hash: { name: digestAlgorithm } }
		: { name: "Ed25519" };

	return subtle.verify(
		verifyParams as AlgorithmIdentifier,
		key,
		new Uint8Array(signature).buffer as ArrayBuffer,
		new Uint8Array(data).buffer as ArrayBuffer,
	);
}

export async function verifyDataIntegrityProof(args: {
	credential: Vcdm2Credential;
	proof: DataIntegrityProof;
	publicKey: JWK;
	subtle: SubtleCrypto;
	httpClient: HttpClient;
}): Promise<DataIntegrityResult> {
	const { credential, proof, publicKey, subtle, httpClient } = args;

	const cryptosuiteName = resolveCryptosuite(proof);
	const suite = cryptosuiteName ? SUITES[cryptosuiteName] : undefined;
	if (!cryptosuiteName || !suite) {
		return {
			success: false,
			failure: { kind: "unsupported-cryptosuite", cryptosuite: cryptosuiteName ?? proof.type },
		};
	}

	if (typeof proof.proofValue !== "string") {
		return { success: false, failure: { kind: "invalid-proof", message: "proof is missing proofValue" } };
	}

	let signature: Uint8Array;
	try {
		signature = multibaseDecode(proof.proofValue);
	} catch (err) {
		const message = errorMessage(err);
		return { success: false, failure: { kind: "invalid-proof", message } };
	}

	// The proof configuration is the proof without its own proofValue, and
	// inherits the credential's context so it canonicalizes in the same
	// vocabulary. (VC-DI §4.2)
	const { proofValue: _omitted, ...proofConfig } = proof as Record<string, unknown>;
	const proofConfigDocument: Record<string, unknown> = {
		...proofConfig,
		"@context": (credential as Record<string, unknown>)["@context"],
	};

	// The document being signed is the credential without any proof member.
	const { proof: _proofOmitted, ...unsecuredCredential } = credential as Record<string, unknown>;

	let canonicalProofConfig: string;
	let canonicalDocument: string;
	try {
		canonicalProofConfig = await canonicalize(proofConfigDocument, suite, httpClient);
		canonicalDocument = await canonicalize(unsecuredCredential, suite, httpClient);
	} catch (err) {
		const message = errorMessage(err);
		const kind = /context|documentLoader|allowlist|HTTP/i.test(message)
			? "context-unresolvable" as const
			: "canonicalization-failed" as const;
		return { success: false, failure: { kind, message } };
	}

	const digestAlgorithm = digestAlgorithmFor(suite, publicKey);
	const encoder = new TextEncoder();

	const proofConfigHash = await sha(subtle, digestAlgorithm, encoder.encode(canonicalProofConfig));
	const documentHash = await sha(subtle, digestAlgorithm, encoder.encode(canonicalDocument));

	// Signed payload is hash(proofConfig) || hash(document). (VC-DI §4.3)
	const verifyData = new Uint8Array(proofConfigHash.length + documentHash.length);
	verifyData.set(proofConfigHash, 0);
	verifyData.set(documentHash, proofConfigHash.length);

	let valid: boolean;
	try {
		valid = await verifySignature({ subtle, suite, publicKey, digestAlgorithm, signature, data: verifyData });
	} catch (err) {
		const message = errorMessage(err);
		return { success: false, failure: { kind: "invalid-proof", message } };
	}

	if (!valid) {
		return { success: false, failure: { kind: "invalid-signature" } };
	}

	return { success: true };
}

export { SUITES as SupportedCryptosuites };
