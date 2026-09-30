import { describe, expect, it, vi } from "vitest";
import * as jose from "jose";
import { canonicalizeJcs } from "./jcs";
import { multikeyToJwk } from "./multibase";
import { verifyDataIntegrityProof } from "./verifyDataIntegrityProof";
import {
	VCDM2_CONTEXT,
	subtle,
	bytesToB64Url,
	b64ToBytes,
	b64UrlToBytes as base64UrlDecode,
	contextHttpClient,
	forbiddenHttpClient,
	offlineHttpClient,
} from "../../testFixtures/vcdm2TestSupport";

const base64UrlEncode = bytesToB64Url;

const genericCredential = {
	"@context": [VCDM2_CONTEXT],
	// Only the generic type, so the display name must fall back.
	type: ["VerifiableCredential"],
	issuer: "did:example:issuer",
	credentialSubject: { id: "did:example:subject" },
};

const credential = {
	"@context": [VCDM2_CONTEXT],
	type: ["VerifiableCredential"],
	issuer: "did:example:issuer",
	credentialSubject: { id: "did:example:subject", name: "Alice" },
};

/**
 * End-to-end exercise of the Data Integrity pipeline using ecdsa-jcs-2019,
 * which needs no JSON-LD context resolution — so this asserts the
 * canonicalize/hash/concatenate/verify sequence itself rather than jsonld's
 * behaviour.
 */
describe("verifyDataIntegrityProof (ecdsa-jcs-2019)", () => {
	const credentialBase = {
		"@context": ["https://www.w3.org/ns/credentials/v2"],
		id: "urn:uuid:0b1f3a4e-1f0a-4c9e-9a1e-2f4f6b1c2d3e",
		type: ["VerifiableCredential", "ExampleCredential"],
		issuer: "did:example:issuer",
		validFrom: "2026-01-01T00:00:00Z",
		credentialSubject: { id: "did:example:subject", name: "Alice" },
	};

	async function signCredential(overrides: { tamperAfterSigning?: boolean } = {}) {
		const keyPair = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
		const publicKey = await subtle.exportKey("jwk", keyPair.publicKey);

		const proofConfig = {
			type: "DataIntegrityProof",
			cryptosuite: "ecdsa-jcs-2019",
			created: "2026-01-01T00:00:00Z",
			verificationMethod: "did:example:issuer#key-1",
			proofPurpose: "assertionMethod",
		};

		const encoder = new TextEncoder();
		const proofConfigHash = new Uint8Array(await subtle.digest(
			"SHA-256",
			encoder.encode(canonicalizeJcs({ ...proofConfig, "@context": credentialBase["@context"] })),
		));
		const documentHash = new Uint8Array(await subtle.digest(
			"SHA-256",
			encoder.encode(canonicalizeJcs(credentialBase)),
		));

		const verifyData = new Uint8Array(proofConfigHash.length + documentHash.length);
		verifyData.set(proofConfigHash, 0);
		verifyData.set(documentHash, proofConfigHash.length);

		const signature = new Uint8Array(await subtle.sign(
			{ name: "ECDSA", hash: { name: "SHA-256" } },
			keyPair.privateKey,
			verifyData.buffer as ArrayBuffer,
		));

		const credential: any = {
			...credentialBase,
			proof: { ...proofConfig, proofValue: `u${base64UrlEncode(signature)}` },
		};

		if (overrides.tamperAfterSigning) {
			credential.credentialSubject = { ...credential.credentialSubject, name: "Mallory" };
		}

		return { credential, publicKey };
	}

	it("verifies a correctly signed credential", async () => {
		const { credential, publicKey } = await signCredential();

		const result = await verifyDataIntegrityProof({
			credential,
			proof: credential.proof,
			publicKey,
			subtle,
			httpClient: forbiddenHttpClient,
		});

		expect(result.success).toBe(true);
	});

	it("rejects a credential modified after signing", async () => {
		const { credential, publicKey } = await signCredential({ tamperAfterSigning: true });

		const result = await verifyDataIntegrityProof({
			credential,
			proof: credential.proof,
			publicKey,
			subtle,
			httpClient: forbiddenHttpClient,
		});

		expect(result.success).toBe(false);
		if (!result.success) expect(result.failure.kind).toBe("invalid-signature");
	});

	it("rejects a proof whose configuration was altered after signing", async () => {
		const { credential, publicKey } = await signCredential();
		// Same signature, different proof purpose: the proof config is part
		// of the signed data, so this must not verify.
		const proof = { ...credential.proof, proofPurpose: "authentication" };

		const result = await verifyDataIntegrityProof({
			credential,
			proof,
			publicKey,
			subtle,
			httpClient: forbiddenHttpClient,
		});

		expect(result.success).toBe(false);
	});

	it("reports an unsupported cryptosuite rather than failing the signature", async () => {
		const { credential, publicKey } = await signCredential();
		const proof = { ...credential.proof, cryptosuite: "ecdsa-sd-2023" };

		const result = await verifyDataIntegrityProof({
			credential,
			proof,
			publicKey,
			subtle,
			httpClient: forbiddenHttpClient,
		});

		expect(result.success).toBe(false);
		if (!result.success) {
			expect(result.failure.kind).toBe("unsupported-cryptosuite");
		}
	});

	it("reports a missing proofValue as an invalid proof", async () => {
		const { credential, publicKey } = await signCredential();
		const { proofValue: _omitted, ...proof } = credential.proof;

		const result = await verifyDataIntegrityProof({
			credential,
			proof: proof as any,
			publicKey,
			subtle,
			httpClient: forbiddenHttpClient,
		});

		expect(result.success).toBe(false);
		if (!result.success) expect(result.failure.kind).toBe("invalid-proof");
	});
});

describe("verifyDataIntegrityProof — RDFC canonicalization", () => {
	async function signRdfc() {
		const keyPair = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
		const publicJwk = await subtle.exportKey("jwk", keyPair.publicKey);

		const proofConfig = {
			type: "DataIntegrityProof",
			cryptosuite: "ecdsa-rdfc-2019",
			created: "2026-01-01T00:00:00Z",
			verificationMethod: "did:example:issuer#key-1",
			proofPurpose: "assertionMethod",
		};

		const jsonld = (await import("jsonld")).default as any;
		const documentLoader = async (url: string) => ({
			contextUrl: null,
			documentUrl: url,
			document: { "@context": { "@vocab": "https://example.org/vocab#" } },
		});
		const canonize = (doc: unknown) => jsonld.canonize(doc, {
			algorithm: "URDNA2015",
			format: "application/n-quads",
			safe: true,
			documentLoader,
		});

		const encoder = new TextEncoder();
		const hash = async (value: string) => new Uint8Array(await subtle.digest("SHA-256", encoder.encode(value)));
		const proofConfigHash = await hash(await canonize({ ...proofConfig, "@context": credential["@context"] }));
		const documentHash = await hash(await canonize(credential));

		const verifyData = new Uint8Array(proofConfigHash.length + documentHash.length);
		verifyData.set(proofConfigHash, 0);
		verifyData.set(documentHash, proofConfigHash.length);

		const signature = new Uint8Array(await subtle.sign(
			{ name: "ECDSA", hash: { name: "SHA-256" } },
			keyPair.privateKey,
			verifyData.buffer as ArrayBuffer,
		));

		return {
			proof: { ...proofConfig, proofValue: `u${bytesToB64Url(signature)}` },
			publicJwk: publicJwk as jose.JWK,
		};
	}

	it("verifies a credential signed with ecdsa-rdfc-2019", async () => {
		const { proof, publicJwk } = await signRdfc();

		const result = await verifyDataIntegrityProof({
			credential: credential as any,
			proof: proof as any,
			publicKey: publicJwk,
			subtle,
			httpClient: contextHttpClient(),
		});

		expect(result.success).toBe(true);
	});

	it("reports a canonicalization failure distinctly from a context failure", async () => {
		const { proof, publicJwk } = await signRdfc();

		// A context that defines no terms makes jsonld's safe mode reject the
		// document; the message says nothing about contexts or HTTP.
		const result = await verifyDataIntegrityProof({
			credential: credential as any,
			proof: proof as any,
			publicKey: publicJwk,
			subtle,
			httpClient: contextHttpClient({ "@context": {} }),
		});

		expect(result.success).toBe(false);
		if (!result.success) expect(result.failure.kind).toBe("canonicalization-failed");
	});

	it("reports a proofValue that is not valid multibase", async () => {
		const { proof, publicJwk } = await signRdfc();

		const result = await verifyDataIntegrityProof({
			credential: credential as any,
			proof: { ...proof, proofValue: "z0OIl" } as any,
			publicKey: publicJwk,
			subtle,
			httpClient: contextHttpClient(),
		});

		expect(result.success).toBe(false);
		if (!result.success) expect(result.failure.kind).toBe("invalid-proof");
	});
});

describe("verifyDataIntegrityProof — EdDSA suites", () => {
	it("verifies a credential signed with eddsa-jcs-2022", async () => {
		const keyPair = await subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]) as CryptoKeyPair;
		const publicJwk = await subtle.exportKey("jwk", keyPair.publicKey);

		const proofConfig = {
			type: "DataIntegrityProof",
			cryptosuite: "eddsa-jcs-2022",
			created: "2026-01-01T00:00:00Z",
			verificationMethod: "did:example:issuer#key-1",
			proofPurpose: "assertionMethod",
		};

		const encoder = new TextEncoder();
		const hash = async (value: string) => new Uint8Array(await subtle.digest("SHA-256", encoder.encode(value)));
		const proofConfigHash = await hash(canonicalizeJcs({ ...proofConfig, "@context": credential["@context"] }));
		const documentHash = await hash(canonicalizeJcs(credential));

		const verifyData = new Uint8Array(proofConfigHash.length + documentHash.length);
		verifyData.set(proofConfigHash, 0);
		verifyData.set(documentHash, proofConfigHash.length);

		const signature = new Uint8Array(await subtle.sign(
			{ name: "Ed25519" },
			keyPair.privateKey,
			verifyData.buffer as ArrayBuffer,
		));

		const result = await verifyDataIntegrityProof({
			credential: credential as any,
			proof: { ...proofConfig, proofValue: `u${bytesToB64Url(signature)}` } as any,
			publicKey: publicJwk as jose.JWK,
			subtle,
			httpClient: contextHttpClient(),
		});

		expect(result.success).toBe(true);
	});

	it("reports a signature that does not verify under Ed25519", async () => {
		const keyPair = await subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]) as CryptoKeyPair;
		const publicJwk = await subtle.exportKey("jwk", keyPair.publicKey);

		const result = await verifyDataIntegrityProof({
			credential: credential as any,
			proof: {
				type: "DataIntegrityProof",
				cryptosuite: "eddsa-jcs-2022",
				verificationMethod: "did:example:issuer#key-1",
				proofPurpose: "assertionMethod",
				proofValue: `u${bytesToB64Url(new Uint8Array(64))}`,
			} as any,
			publicKey: publicJwk as jose.JWK,
			subtle,
			httpClient: contextHttpClient(),
		});

		expect(result.success).toBe(false);
		if (!result.success) expect(result.failure.kind).toBe("invalid-signature");
	});
});

describe("verifyDataIntegrityProof key and suite selection", () => {
	async function signJcs(curve: "P-256" | "P-384", digest: "SHA-256" | "SHA-384", stripCrv = false) {
		const keyPair = await subtle.generateKey({ name: "ECDSA", namedCurve: curve }, true, ["sign", "verify"]);
		const publicJwk = await subtle.exportKey("jwk", keyPair.publicKey) as jose.JWK;

		const proofConfig = {
			type: "DataIntegrityProof",
			cryptosuite: "ecdsa-jcs-2019",
			verificationMethod: "did:example:issuer#key-1",
			proofPurpose: "assertionMethod",
		};

		const encoder = new TextEncoder();
		const hash = async (v: string) => new Uint8Array(await subtle.digest(digest, encoder.encode(v)));
		const a = await hash(canonicalizeJcs({ ...proofConfig, "@context": genericCredential["@context"] }));
		const b = await hash(canonicalizeJcs(genericCredential));
		const data = new Uint8Array(a.length + b.length);
		data.set(a, 0); data.set(b, a.length);

		const signature = new Uint8Array(await subtle.sign(
			{ name: "ECDSA", hash: { name: digest } }, keyPair.privateKey, data.buffer as ArrayBuffer,
		));

		const key = stripCrv ? { ...publicJwk, crv: undefined } : publicJwk;
		return {
			proof: { ...proofConfig, proofValue: `u${bytesToB64Url(signature)}` },
			publicKey: key as jose.JWK,
		};
	}

	it("uses SHA-384 for a P-384 key", async () => {
		const { proof, publicKey } = await signJcs("P-384", "SHA-384");

		const result = await verifyDataIntegrityProof({
			credential: genericCredential as any,
			proof: proof as any,
			publicKey,
			subtle,
			httpClient: offlineHttpClient,
		});

		expect(result.success).toBe(true);
	});

	it("falls back to P-256 for the named curve, but still cannot import a JWK with no crv", async () => {
		// The `?? "P-256"` fallback only supplies the algorithm's namedCurve;
		// WebCrypto separately requires the JWK itself to carry `crv`, so a
		// key without one is reported as an invalid proof rather than
		// silently verified against a guessed curve.
		const { proof, publicKey } = await signJcs("P-256", "SHA-256", true);

		const result = await verifyDataIntegrityProof({
			credential: genericCredential as any,
			proof: proof as any,
			publicKey,
			subtle,
			httpClient: offlineHttpClient,
		});

		expect(result.success).toBe(false);
		if (!result.success) expect(result.failure.kind).toBe("invalid-proof");
	});

	it("names the proof type when reporting an unknown cryptosuite", async () => {
		const result = await verifyDataIntegrityProof({
			credential: genericCredential as any,
			proof: {
				type: "SomeUnknownProofType",
				verificationMethod: "did:example:issuer#key-1",
				proofPurpose: "assertionMethod",
				proofValue: "uAAAA",
			} as any,
			publicKey: { kty: "EC", crv: "P-256" } as jose.JWK,
			subtle,
			httpClient: offlineHttpClient,
		});

		expect(result.success).toBe(false);
		if (!result.success && result.failure.kind === "unsupported-cryptosuite") {
			expect(result.failure.cryptosuite).toBe("SomeUnknownProofType");
		}
	});

	it("reports a key that cannot be imported as an invalid proof", async () => {
		const { proof } = await signJcs("P-256", "SHA-256");

		const result = await verifyDataIntegrityProof({
			credential: genericCredential as any,
			proof: proof as any,
			publicKey: { kty: "EC", crv: "P-256", x: "!!", y: "!!" } as jose.JWK,
			subtle,
			httpClient: offlineHttpClient,
		});

		expect(result.success).toBe(false);
		if (!result.success) expect(result.failure.kind).toBe("invalid-proof");
	});
});

describe("non-Error throwables are stringified rather than crashing", () => {
	it("reports a canonicalization step that throws a non-Error", async () => {
		// jsonld is loaded lazily inside the rdfc path; make its import reject
		// with a bare string to exercise the String(err) fallback.
		vi.doMock("jsonld", () => { throw "boom"; });

		const result = await verifyDataIntegrityProof({
			credential: genericCredential as any,
			proof: {
				type: "DataIntegrityProof",
				cryptosuite: "ecdsa-rdfc-2019",
				verificationMethod: "did:example:issuer#key-1",
				proofPurpose: "assertionMethod",
				proofValue: "uAAAA",
			} as any,
			publicKey: { kty: "EC", crv: "P-256" } as jose.JWK,
			subtle,
			httpClient: offlineHttpClient,
		});

		expect(result.success).toBe(false);
		vi.doUnmock("jsonld");
	});
});
