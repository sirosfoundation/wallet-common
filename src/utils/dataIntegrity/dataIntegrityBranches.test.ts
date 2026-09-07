import { describe, expect, it, vi } from "vitest";
import * as jose from "jose";
import { canonicalizeJcs } from "./jcs";
import { multikeyToJwk } from "./multibase";
import { verifyDataIntegrityProof } from "./verifyDataIntegrityProof";
import { isMdoc } from "../detectCredentialFormat";
import { VCDM2JoseVerifier } from "../../credential-verifiers/VCDM2JoseVerifier";
import { VCDM2LdpVerifier } from "../../credential-verifiers/VCDM2LdpVerifier";
import { CredentialVerificationError } from "../../error";
import { TEST_CERT_DER_B64, TEST_CERT_PEM, TEST_PRIVATE_KEY_PKCS8_B64, UNRELATED_CERT_PEM } from "../../testFixtures/vcdm2TestCertificate";
import type { Context, HttpClient, PublicKeyResolverEngineI } from "../../interfaces";

const subtle = globalThis.crypto.subtle;

const VCDM2_CONTEXT = "https://www.w3.org/ns/credentials/v2";

function b64ToBytes(value: string): Uint8Array {
	const binary = atob(value);
	return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

function bytesToB64Url(bytes: Uint8Array): string {
	let binary = "";
	for (const b of bytes) binary += String.fromCharCode(b);
	return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * A document loader stub. `@vocab` lets every term resolve, so jsonld's safe
 * mode is satisfied without shipping the real 30 KB VCDM 2.0 context.
 */
function contextHttpClient(contextDocument: unknown = { "@context": { "@vocab": "https://example.org/vocab#" } }): HttpClient {
	return {
		get: vi.fn(async () => ({ status: 200, headers: {}, data: contextDocument })),
		post: vi.fn(),
	} as unknown as HttpClient;
}

const credential = {
	"@context": [VCDM2_CONTEXT],
	type: ["VerifiableCredential"],
	issuer: "did:example:issuer",
	credentialSubject: { id: "did:example:subject", name: "Alice" },
};

describe("isMdoc defensive path", () => {
	it("returns false rather than throwing when the input is not a string", () => {
		expect(isMdoc(undefined as unknown as string)).toBe(false);
		expect(isMdoc(null as unknown as string)).toBe(false);
	});
});

describe("point decompression covers both y parities", () => {
	it("recovers x and y whichever parity the point has", async () => {
		const seen = new Set<number>();

		// Parity depends on the generated key, so generate until both the
		// even and odd cases have been exercised.
		for (let attempt = 0; attempt < 40 && seen.size < 2; attempt += 1) {
			const keyPair = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
			const jwk = await subtle.exportKey("jwk", keyPair.publicKey);
			const dec = (v: string) => {
				const padded = v + "=".repeat((4 - (v.length % 4)) % 4);
				return Uint8Array.from(atob(padded.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
			};
			const x = dec(jwk.x as string);
			const y = dec(jwk.y as string);
			const parity = y[y.length - 1] & 1;
			seen.add(parity);

			const compressed = new Uint8Array([parity === 1 ? 0x03 : 0x02, ...x]);
			const decoded = multikeyToJwk(new Uint8Array([0x80, 0x24, ...compressed]));
			expect(decoded.x).toBe(jwk.x);
			expect(decoded.y).toBe(jwk.y);
		}

		expect(seen.size).toBe(2);
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

describe("VCDM2JoseVerifier with a real x5c chain", () => {
	async function signWithCertKey() {
		const pkcs8 = b64ToBytes(TEST_PRIVATE_KEY_PKCS8_B64);
		const privateKey = await subtle.importKey(
			"pkcs8",
			pkcs8.buffer as ArrayBuffer,
			{ name: "ECDSA", namedCurve: "P-256" },
			false,
			["sign"],
		);

		return new jose.SignJWT(credential)
			.setProtectedHeader({ alg: "ES256", typ: "vc+jwt", x5c: [TEST_CERT_DER_B64] })
			.sign(privateKey as unknown as jose.KeyLike);
	}

	const resolver = {
		register: vi.fn(),
		resolve: vi.fn(async () => ({ success: false as const, error: "CannotResolvePublicKey" as any })),
	} as unknown as PublicKeyResolverEngineI;

	it("defaults to delegated trust when the context sets no trust fields", async () => {
		const jwt = await signWithCertKey();
		const verifier = VCDM2JoseVerifier({
			// Neither delegateTrustToBackend nor trustedCertificates present.
			context: { clockTolerance: 60, lang: "en-US", subtle } as Context,
			pkResolverEngine: resolver,
			httpClient: contextHttpClient(),
		});

		const result = await verifier.verify({ rawCredential: jwt, opts: {} });
		expect(result.success).toBe(true);
	});

	it("verifies using the certificate in the header", async () => {
		const jwt = await signWithCertKey();
		const verifier = VCDM2JoseVerifier({
			context: { clockTolerance: 60, lang: "en-US", subtle, delegateTrustToBackend: true } as Context,
			pkResolverEngine: resolver,
			httpClient: contextHttpClient(),
		});

		const result = await verifier.verify({ rawCredential: jwt, opts: {} });
		expect(result.success).toBe(true);
	});

	it("accepts the chain when the certificate is itself a configured trust anchor", async () => {
		const jwt = await signWithCertKey();
		const verifier = VCDM2JoseVerifier({
			context: {
				clockTolerance: 60,
				lang: "en-US",
				subtle,
				delegateTrustToBackend: false,
				trustedCertificates: [TEST_CERT_PEM],
			} as Context,
			pkResolverEngine: resolver,
			httpClient: contextHttpClient(),
		});

		const result = await verifier.verify({ rawCredential: jwt, opts: {} });
		expect(result.success).toBe(true);
	});

	it("rejects a well-formed certificate that chains to no configured anchor", async () => {
		const jwt = await signWithCertKey();
		// A genuine, well-formed anchor that this certificate does not chain
		// to, so validation returns false rather than throwing.
		const otherAnchor = UNRELATED_CERT_PEM;

		const verifier = VCDM2JoseVerifier({
			context: {
				clockTolerance: 60,
				lang: "en-US",
				subtle,
				delegateTrustToBackend: false,
				trustedCertificates: [otherAnchor],
			} as Context,
			pkResolverEngine: resolver,
			httpClient: contextHttpClient(),
		});

		const result = await verifier.verify({ rawCredential: jwt, opts: {} });
		expect(result.success).toBe(false);
		if (!result.success) expect(result.error).toBe(CredentialVerificationError.NotTrustedIssuer);
	});
});
