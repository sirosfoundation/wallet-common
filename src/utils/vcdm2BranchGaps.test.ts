import { describe, expect, it, vi } from "vitest";
import * as jose from "jose";
import { decodeEnvelopedVcdm2, isVcdm2Credential } from "./vcdm2";
import { multikeyToJwk } from "./dataIntegrity/multibase";
import { verifyDataIntegrityProof } from "./dataIntegrity/verifyDataIntegrityProof";
import { canonicalizeJcs } from "./dataIntegrity/jcs";
import { detectCredentialFormat, isMdoc } from "./detectCredentialFormat";
import { VCDM2JoseParser } from "../credential-parsers/VCDM2JoseParser";
import { VCDM2LdpParser } from "../credential-parsers/VCDM2LdpParser";
import { VCDM2JoseVerifier } from "../credential-verifiers/VCDM2JoseVerifier";
import { VerifiableCredentialFormat } from "../types";
import { CredentialVerificationError } from "../error";
import type { Context, HttpClient, PublicKeyResolverEngineI } from "../interfaces";

const subtle = globalThis.crypto.subtle;

const offlineHttpClient: HttpClient = {
	async get() { return { status: 404, headers: {}, data: null }; },
	async post() { return { status: 404, headers: {}, data: null }; },
};

function enc(value: object): string {
	const bytes = new TextEncoder().encode(JSON.stringify(value));
	let binary = "";
	for (const b of bytes) binary += String.fromCharCode(b);
	return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function bytesToB64Url(bytes: Uint8Array): string {
	let binary = "";
	for (const b of bytes) binary += String.fromCharCode(b);
	return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

const genericCredential = {
	"@context": ["https://www.w3.org/ns/credentials/v2"],
	// Only the generic type, so the display name must fall back.
	type: ["VerifiableCredential"],
	issuer: "did:example:issuer",
	credentialSubject: { id: "did:example:subject" },
};

describe("isVcdm2Credential structural guards", () => {
	it("rejects an array", () => {
		expect(isVcdm2Credential([])).toBe(false);
	});

	it("rejects null and primitives", () => {
		expect(isVcdm2Credential(null)).toBe(false);
		expect(isVcdm2Credential("string")).toBe(false);
	});

	it("rejects a credential with no type", () => {
		expect(isVcdm2Credential({
			"@context": ["https://www.w3.org/ns/credentials/v2"],
			issuer: "did:example:issuer",
		})).toBe(false);
	});

	it("rejects a credential with no issuer", () => {
		expect(isVcdm2Credential({
			"@context": ["https://www.w3.org/ns/credentials/v2"],
			type: ["VerifiableCredential"],
		})).toBe(false);
	});

	it("rejects an empty or non-array @context", () => {
		expect(isVcdm2Credential({ "@context": [], type: [], issuer: "x" })).toBe(false);
		expect(isVcdm2Credential({ "@context": "v2", type: [], issuer: "x" })).toBe(false);
	});
});

describe("decodeEnvelopedVcdm2", () => {
	it("declines a JWS with no typ whose payload is not a VCDM 2.0 credential", () => {
		expect(decodeEnvelopedVcdm2(`${enc({ alg: "ES256" })}.${enc({ sub: "x" })}.sig`)).toBeNull();
	});

	it("accepts a JWS with no typ whose payload is itself a VCDM 2.0 credential", () => {
		const decoded = decodeEnvelopedVcdm2(`${enc({ alg: "ES256" })}.${enc(genericCredential)}.sig`);
		expect(decoded).not.toBeNull();
		expect(decoded?.payload.issuer).toBe("did:example:issuer");
	});

	it("declines a JWS whose payload wraps a VCDM 1.1 credential", () => {
		expect(decodeEnvelopedVcdm2(`${enc({ alg: "ES256" })}.${enc({ vc: { type: ["X"] } })}.sig`)).toBeNull();
	});
});

describe("isMdoc recognises every accepted CBOR prefix", () => {
	const prefixes: Array<[number, number]> = [
		[0xa2, 0x6a], [0xb9, 0x00], [0xa3, 0x67], [0xa3, 0x66], [0xa3, 0x69],
	];

	it.each(prefixes)("accepts a document starting %s %s", (first, second) => {
		const raw = bytesToB64Url(new Uint8Array([first, second, 0x00, 0x00]));
		expect(isMdoc(raw)).toBe(true);
		expect(detectCredentialFormat(raw)).toBe(VerifiableCredentialFormat.MSO_MDOC);
	});

	it("rejects a CBOR prefix it does not recognise", () => {
		expect(isMdoc(bytesToB64Url(new Uint8Array([0xa3, 0x99, 0, 0])))).toBe(false);
	});
});

describe("multikeyToJwk length guard", () => {
	it("rejects a multikey shorter than its own prefix", () => {
		expect(() => multikeyToJwk(new Uint8Array([0xed]))).toThrow(/unsupported key type/);
	});
});

describe("parsers fall back to a generic name", () => {
	it("VCDM2JoseParser names a credential with only the generic type", async () => {
		const parser = VCDM2JoseParser({ context: { subtle } as Context, httpClient: offlineHttpClient });
		const raw = `${enc({ alg: "ES256", typ: "vc+jwt" })}.${enc(genericCredential)}.sig`;

		const result = await parser.parse({ rawCredential: raw });
		expect(result.success).toBe(true);
		if (result.success) expect(await result.value.metadata.credential.name()).toBe("Verifiable Credential");
	});

	it("VCDM2LdpParser names a credential with only the generic type", async () => {
		const parser = VCDM2LdpParser({ context: { subtle } as Context, httpClient: offlineHttpClient });

		const result = await parser.parse({ rawCredential: genericCredential });
		expect(result.success).toBe(true);
		if (result.success) expect(await result.value.metadata.credential.name()).toBe("Verifiable Credential");
	});

	it("VCDM2JoseParser carries iat and nbf through to validity info", async () => {
		const parser = VCDM2JoseParser({ context: { subtle } as Context, httpClient: offlineHttpClient });
		const raw = `${enc({ alg: "ES256", typ: "vc+jwt" })}.${enc({
			...genericCredential, iat: 1700000000, nbf: 1700000001,
		})}.sig`;

		const result = await parser.parse({ rawCredential: raw });
		expect(result.success).toBe(true);
		if (!result.success) return;
		expect(result.value.validityInfo.signed).toEqual(new Date(1700000000 * 1000));
		expect(result.value.validityInfo.validFrom).toEqual(new Date(1700000001 * 1000));
	});
});

describe("VCDM2JoseVerifier context defaults", () => {
	it("defaults to delegating trust when the context does not say", async () => {
		const { publicKey, privateKey } = await jose.generateKeyPair("ES256", { extractable: true });
		const jwt = await new jose.SignJWT(genericCredential)
			.setProtectedHeader({ alg: "ES256", typ: "vc+jwt" })
			.sign(privateKey);

		// No delegateTrustToBackend and no trustedCertificates set at all.
		const verifier = VCDM2JoseVerifier({
			context: { clockTolerance: 60, lang: "en-US", subtle } as Context,
			pkResolverEngine: {
				register: vi.fn(),
				resolve: vi.fn(async () => ({ success: true as const, value: { jwk: await jose.exportJWK(publicKey) } })),
			} as unknown as PublicKeyResolverEngineI,
			httpClient: offlineHttpClient,
		});

		const result = await verifier.verify({ rawCredential: jwt, opts: {} });
		expect(result.success).toBe(true);
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
