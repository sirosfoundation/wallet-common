import { describe, expect, it, vi } from "vitest";
import * as jose from "jose";
import { VCDM2LdpVerifier } from "./VCDM2LdpVerifier";
import { CredentialVerificationError } from "../error";
import { canonicalizeJcs } from "../utils/dataIntegrity/jcs";
import {
	VCDM2_CONTEXT,
	b64ToBytes,
	bytesToB64Url,
	contextHttpClient,
	makeContext,
	makeResolver,
	offlineHttpClient,
	subtle,
} from "../testFixtures/vcdm2TestSupport";
import type { Context, PublicKeyResolverEngineI } from "../interfaces";

const ISSUER = "https://issuer.example";

const credential = {
	"@context": [VCDM2_CONTEXT],
	type: ["VerifiableCredential"],
	issuer: "did:example:issuer",
	credentialSubject: { id: "did:example:subject", name: "Alice" },
};

const httpClient = offlineHttpClient;

const credentialBody = {
	"@context": ["https://www.w3.org/ns/credentials/v2"],
	type: ["VerifiableCredential"],
	issuer: "did:example:issuer",
	credentialSubject: { id: "did:example:subject" },
};

async function signEnveloped(extras: Record<string, unknown> = {}) {
	const { publicKey, privateKey } = await jose.generateKeyPair("ES256", { extractable: true });
	const publicJwk = await jose.exportJWK(publicKey);

	const jwt = await new jose.SignJWT({ ...credentialBody, ...extras })
		.setProtectedHeader({ alg: "ES256", typ: "vc+jwt" })
		.sign(privateKey);

	return { jwt, publicJwk, privateKey };
}

describe("VCDM2LdpVerifier", () => {
	/** Sign `credentialBase` with ecdsa-jcs-2019, which needs no JSON-LD contexts. */
	async function signLdp(options: { verificationMethod?: string; cryptosuite?: string } = {}) {
		const keyPair = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
		const publicJwk = await subtle.exportKey("jwk", keyPair.publicKey);

		const proofConfig = {
			type: "DataIntegrityProof",
			cryptosuite: options.cryptosuite ?? "ecdsa-jcs-2019",
			created: "2026-01-01T00:00:00Z",
			verificationMethod: options.verificationMethod ?? "did:example:issuer#key-1",
			proofPurpose: "assertionMethod",
		};

		const encoder = new TextEncoder();
		const hash = async (value: string) => new Uint8Array(await subtle.digest("SHA-256", encoder.encode(value)));
		const proofConfigHash = await hash(canonicalizeJcs({ ...proofConfig, "@context": credentialBody["@context"] }));
		const documentHash = await hash(canonicalizeJcs(credentialBody));

		const verifyData = new Uint8Array(proofConfigHash.length + documentHash.length);
		verifyData.set(proofConfigHash, 0);
		verifyData.set(documentHash, proofConfigHash.length);

		const signature = new Uint8Array(await subtle.sign(
			{ name: "ECDSA", hash: { name: "SHA-256" } },
			keyPair.privateKey,
			verifyData.buffer as ArrayBuffer,
		));

		let binary = "";
		for (const b of signature) binary += String.fromCharCode(b);
		const proofValue = `u${btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")}`;

		return {
			credential: { ...credentialBody, proof: { ...proofConfig, proofValue } },
			publicJwk: publicJwk as jose.JWK,
		};
	}

	it("verifies a correctly signed Data Integrity credential", async () => {
		const { credential, publicJwk } = await signLdp();
		const verifier = VCDM2LdpVerifier({
			context: makeContext(),
			pkResolverEngine: makeResolver(publicJwk),
			httpClient,
		});

		const result = await verifier.verify({ rawCredential: credential, opts: {} });
		expect(result.success).toBe(true);
		if (result.success) expect(result.value.holderPublicKey).toEqual({});
	});

	it("accepts the credential as JSON text", async () => {
		const { credential, publicJwk } = await signLdp();
		const verifier = VCDM2LdpVerifier({
			context: makeContext(),
			pkResolverEngine: makeResolver(publicJwk),
			httpClient,
		});

		const result = await verifier.verify({ rawCredential: JSON.stringify(credential), opts: {} });
		expect(result.success).toBe(true);
	});

	it("does not start on something that is not a VCDM 2.0 credential", async () => {
		const verifier = VCDM2LdpVerifier({
			context: makeContext(),
			pkResolverEngine: makeResolver(null),
			httpClient,
		});

		const result = await verifier.verify({ rawCredential: "nope", opts: {} });
		expect(result.success).toBe(false);
		if (!result.success) expect(result.error).toBe(CredentialVerificationError.VerificationProcessNotStarted);
	});

	it("reports a credential with no proof at all", async () => {
		const verifier = VCDM2LdpVerifier({
			context: makeContext(),
			pkResolverEngine: makeResolver(null),
			httpClient,
		});

		const result = await verifier.verify({ rawCredential: credentialBody, opts: {} });
		expect(result.success).toBe(false);
		if (!result.success) expect(result.error).toBe(CredentialVerificationError.MissingDataIntegrityProof);
	});

	it("reports an unsupported cryptosuite rather than a signature failure", async () => {
		const { credential, publicJwk } = await signLdp({ cryptosuite: "ecdsa-sd-2023" });
		const verifier = VCDM2LdpVerifier({
			context: makeContext(),
			pkResolverEngine: makeResolver(publicJwk),
			httpClient,
		});

		const result = await verifier.verify({ rawCredential: credential, opts: {} });
		expect(result.success).toBe(false);
		if (!result.success) expect(result.error).toBe(CredentialVerificationError.UnsupportedCryptosuite);
	});

	it("reports a proof whose type names no known suite", async () => {
		const { credential, publicJwk } = await signLdp();
		const proof = { ...credential.proof, type: "MysterySignature2099" };
		delete (proof as Record<string, unknown>).cryptosuite;

		const verifier = VCDM2LdpVerifier({
			context: makeContext(),
			pkResolverEngine: makeResolver(publicJwk),
			httpClient,
		});

		const result = await verifier.verify({ rawCredential: { ...credential, proof }, opts: {} });
		expect(result.success).toBe(false);
		if (!result.success) expect(result.error).toBe(CredentialVerificationError.UnsupportedCryptosuite);
	});

	it("reports when the verification method cannot be resolved", async () => {
		const { credential } = await signLdp();
		const verifier = VCDM2LdpVerifier({
			context: makeContext(),
			pkResolverEngine: makeResolver(null),
			httpClient,
		});

		const result = await verifier.verify({ rawCredential: credential, opts: {} });
		expect(result.success).toBe(false);
		if (!result.success) expect(result.error).toBe(CredentialVerificationError.CannotResolveIssuerPublicKey);
	});

	it("retries resolution against the controller when the fragment form fails", async () => {
		const { credential, publicJwk } = await signLdp({ verificationMethod: "did:example:issuer#key-1" });

		const resolve = vi.fn(async ({ identifier }: { identifier: string }) => (
			identifier.includes("#")
				? { success: false as const, error: "CannotResolvePublicKey" as any }
				: { success: true as const, value: { jwk: publicJwk } }
		));
		const resolver = { register: vi.fn(), resolve } as unknown as PublicKeyResolverEngineI;

		const verifier = VCDM2LdpVerifier({ context: makeContext(), pkResolverEngine: resolver, httpClient });
		const result = await verifier.verify({ rawCredential: credential, opts: {} });

		expect(result.success).toBe(true);
		expect(resolve).toHaveBeenCalledTimes(2);
	});

	it("resolves a did:key verification method without consulting the resolver", async () => {
		// did:key carries the key in the identifier, so a resolver that always
		// fails must not prevent verification — though the key will not match,
		// so this asserts the failure is a signature one, not a resolution one.
		const { credential } = await signLdp({
			verificationMethod: "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6Mkha",
		});
		const resolver = makeResolver(null);
		const verifier = VCDM2LdpVerifier({ context: makeContext(), pkResolverEngine: resolver, httpClient });

		const result = await verifier.verify({ rawCredential: credential, opts: {} });
		expect(result.success).toBe(false);
		expect(resolver.resolve).not.toHaveBeenCalled();
	});

	it("falls back to the resolver when a did:key cannot be decoded", async () => {
		const { credential, publicJwk } = await signLdp({ verificationMethod: "did:key:zNotBase58!!" });
		const resolver = makeResolver(publicJwk);
		const verifier = VCDM2LdpVerifier({ context: makeContext(), pkResolverEngine: resolver, httpClient });

		const result = await verifier.verify({ rawCredential: credential, opts: {} });
		expect(result.success).toBe(false);
		if (!result.success) expect(result.error).toBe(CredentialVerificationError.CannotResolveIssuerPublicKey);
	});

	it("rejects a credential modified after signing", async () => {
		const { credential, publicJwk } = await signLdp();
		const tampered = { ...credential, credentialSubject: { id: "did:example:mallory" } };

		const verifier = VCDM2LdpVerifier({
			context: makeContext(),
			pkResolverEngine: makeResolver(publicJwk),
			httpClient,
		});

		const result = await verifier.verify({ rawCredential: tampered, opts: {} });
		expect(result.success).toBe(false);
		if (!result.success) expect(result.error).toBe(CredentialVerificationError.InvalidSignature);
	});

	it("reports an invalid proof when proofValue is missing", async () => {
		const { credential, publicJwk } = await signLdp();
		const { proofValue: _omitted, ...proof } = credential.proof;

		const verifier = VCDM2LdpVerifier({
			context: makeContext(),
			pkResolverEngine: makeResolver(publicJwk),
			httpClient,
		});

		const result = await verifier.verify({ rawCredential: { ...credential, proof }, opts: {} });
		expect(result.success).toBe(false);
		if (!result.success) expect(result.error).toBe(CredentialVerificationError.InvalidFormat);
	});

	it("accepts a proof set when any one proof verifies", async () => {
		const { credential, publicJwk } = await signLdp();
		const bogus = { ...credential.proof, proofValue: "uAAAA" };

		const verifier = VCDM2LdpVerifier({
			context: makeContext(),
			pkResolverEngine: makeResolver(publicJwk),
			httpClient,
		});

		const result = await verifier.verify({
			rawCredential: { ...credential, proof: [bogus, credential.proof] },
			opts: {},
		});
		expect(result.success).toBe(true);
	});

	it("rejects a credential whose shape fails schema validation", async () => {
		const verifier = VCDM2LdpVerifier({
			context: makeContext(),
			pkResolverEngine: makeResolver(null),
			httpClient,
		});

		// Passes the structural VCDM 2.0 check but violates the schema:
		// `issuer` must be a string or an object with an id.
		const result = await verifier.verify({
			rawCredential: {
				"@context": ["https://www.w3.org/ns/credentials/v2"],
				type: ["VerifiableCredential"],
				issuer: 42,
				credentialSubject: {},
			},
			opts: {},
		});

		expect(result.success).toBe(false);
		if (!result.success) expect(result.error).toBe(CredentialVerificationError.InvalidFormat);
	});
});

describe("VCDM2LdpVerifier cryptosuite gating", () => {
	it("reports an unsupported suite rather than an unresolvable key", async () => {
		// resolveCryptosuite reports whatever the proof claims, so before the
		// supported-set check an unsupported suite reached key resolution and
		// surfaced as CannotResolveIssuerPublicKey whenever the verification
		// method was unavailable. Raised in review by Copilot.
		const credential = {
			"@context": ["https://www.w3.org/ns/credentials/v2"],
			type: ["VerifiableCredential"],
			issuer: "did:example:issuer",
			credentialSubject: { id: "did:example:subject" },
			proof: {
				type: "DataIntegrityProof",
				cryptosuite: "ecdsa-sd-2023",
				verificationMethod: "did:example:issuer#nonexistent",
				proofPurpose: "assertionMethod",
				proofValue: "uAAAA",
			},
		};

		const verifier = VCDM2LdpVerifier({
			context: makeContext(),
			pkResolverEngine: makeResolver(null),
			httpClient,
		});

		const result = await verifier.verify({ rawCredential: JSON.stringify(credential), opts: {} });
		expect(result.success).toBe(false);
		if (!result.success) expect(result.error).toBe(CredentialVerificationError.UnsupportedCryptosuite);
	});
});

describe("VCDM2LdpVerifier error mapping", () => {
	const proofBase = {
		type: "DataIntegrityProof",
		cryptosuite: "ecdsa-rdfc-2019",
		created: "2026-01-01T00:00:00Z",
		verificationMethod: "did:example:issuer#key-1",
		proofPurpose: "assertionMethod",
		proofValue: "uAAAA",
	};

	function ldpVerifier(httpClient: HttpClient) {
		return VCDM2LdpVerifier({
			context: makeContext(),
			pkResolverEngine: {
				register: vi.fn(),
				resolve: vi.fn(async () => ({
					success: true as const,
					value: { jwk: { kty: "EC", crv: "P-256", x: "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU", y: "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0" } as jose.JWK },
				})),
			} as unknown as PublicKeyResolverEngineI,
			httpClient,
		});
	}

	it("maps a refused JSON-LD context to UnresolvableJsonLdContext", async () => {
		// The credential references a context outside the loader's allowlist,
		// so canonicalization cannot proceed.
		const credential = {
			"@context": ["https://www.w3.org/ns/credentials/v2", "https://not-allowed.example/v1"],
			type: ["VerifiableCredential"],
			issuer: ISSUER,
			credentialSubject: { id: "did:example:subject" },
			proof: proofBase,
		};

		const httpClient: HttpClient = {
			get: vi.fn(async () => ({ status: 200, headers: {}, data: { "@context": {} } })),
			post: vi.fn(),
		} as unknown as HttpClient;

		const result = await ldpVerifier(httpClient).verify({ rawCredential: credential, opts: {} });
		expect(result.success).toBe(false);
		if (!result.success) expect(result.error).toBe(CredentialVerificationError.UnresolvableJsonLdContext);
	});

	it("maps a context that cannot be fetched to UnresolvableJsonLdContext", async () => {
		const credential = {
			"@context": ["https://www.w3.org/ns/credentials/v2"],
			type: ["VerifiableCredential"],
			issuer: ISSUER,
			credentialSubject: { id: "did:example:subject" },
			proof: proofBase,
		};

		const httpClient: HttpClient = {
			get: vi.fn(async () => ({ status: 500, headers: {}, data: null })),
			post: vi.fn(),
		} as unknown as HttpClient;

		const result = await ldpVerifier(httpClient).verify({ rawCredential: credential, opts: {} });
		expect(result.success).toBe(false);
		if (!result.success) expect(result.error).toBe(CredentialVerificationError.UnresolvableJsonLdContext);
	});
});

describe("VCDM2LdpVerifier canonicalization failure mapping", () => {
	it("maps a canonicalization failure to CanonicalizationFailed", async () => {
		const publicJwk = await subtle.exportKey(
			"jwk",
			(await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])).publicKey,
		);

		const verifier = VCDM2LdpVerifier({
			context: { clockTolerance: 60, lang: "en-US", subtle } as Context,
			pkResolverEngine: {
				register: vi.fn(),
				resolve: vi.fn(async () => ({ success: true as const, value: { jwk: publicJwk as jose.JWK } })),
			} as unknown as PublicKeyResolverEngineI,
			httpClient: contextHttpClient({ "@context": {} }),
		});

		const result = await verifier.verify({
			rawCredential: {
				...credential,
				proof: {
					type: "DataIntegrityProof",
					cryptosuite: "ecdsa-rdfc-2019",
					verificationMethod: "did:example:issuer#key-1",
					proofPurpose: "assertionMethod",
					proofValue: "uAAAA",
				},
			},
			opts: {},
		});

		expect(result.success).toBe(false);
		if (!result.success) expect(result.error).toBe(CredentialVerificationError.CanonicalizationFailed);
	});
});
