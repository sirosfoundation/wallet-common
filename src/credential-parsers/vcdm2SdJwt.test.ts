import { describe, expect, it, vi } from "vitest";
import * as jose from "jose";
import { VCDM2SdJwtParser } from "./VCDM2SdJwtParser";
import { VCDM2SdJwtVerifier } from "../credential-verifiers/VCDM2SdJwtVerifier";
import { CredentialParsingError, CredentialVerificationError } from "../error";
import { VerifiableCredentialFormat } from "../types";
import { detectCredentialFormat } from "../utils/detectCredentialFormat";
import { splitSdJwt, decodeVcdm2SdJwt } from "../utils/vcdm2";
import { envelopedMediaTypeFor, wrapCredentialForPresentation } from "../utils/vcdm2Presentation";
import { TEST_CERT_DER_B64, TEST_CERT_PEM, TEST_PRIVATE_KEY_PKCS8_B64, UNRELATED_CERT_PEM } from "../testFixtures/vcdm2TestCertificate";
import type { Context, HttpClient, PublicKeyResolverEngineI } from "../interfaces";

const subtle = globalThis.crypto.subtle;

/**
 * W3C VCDM 2.0 carried inside an SD-JWT, as DIIP v5 specifies and as the
 * eduwallet proeftuin issues it: a VCDM 2.0 body, a `type` array rather than
 * a `vct`, and a trailing `~` because every claim is disclosed.
 */
const ISSUER = "https://mbob.issuer.dev.eduwallet.nl";

const credentialBody = {
	"@context": ["https://www.w3.org/ns/credentials/v2"],
	type: ["VerifiableCredential", "StudentCardCredential"],
	issuer: ISSUER,
	credentialSubject: { id: "did:example:subject", given_name: "Alice" },
};

function enc(value: object): string {
	const bytes = new TextEncoder().encode(JSON.stringify(value));
	let binary = "";
	for (const b of bytes) binary += String.fromCharCode(b);
	return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function unsignedSdJwt(payload: object, header: object = { alg: "ES256", typ: "vc+sd-jwt" }): string {
	return `${enc(header)}.${enc(payload)}.sig~`;
}

function makeContext(overrides: Partial<Context> = {}): Context {
	return {
		clockTolerance: 60,
		lang: "en-US",
		subtle,
		delegateTrustToBackend: true,
		trustedCertificates: [],
		...overrides,
	} as Context;
}

const offlineHttpClient: HttpClient = {
	async get() { return { status: 404, headers: {}, data: null }; },
	async post() { return { status: 404, headers: {}, data: null }; },
};

function resolverFor(jwk: jose.JWK | null): PublicKeyResolverEngineI {
	return {
		register: vi.fn(),
		resolve: vi.fn(async () => (
			jwk ? { success: true as const, value: { jwk } } : { success: false as const, error: "CannotResolvePublicKey" as any }
		)),
	} as unknown as PublicKeyResolverEngineI;
}

/** Sign the issuer JWT for real and append the empty disclosure section. */
async function signedSdJwt(payload: object = credentialBody, header: Record<string, unknown> = {}) {
	const { publicKey, privateKey } = await jose.generateKeyPair("ES256", { extractable: true });
	const jwt = await new jose.SignJWT(payload as jose.JWTPayload)
		.setProtectedHeader({ alg: "ES256", typ: "vc+sd-jwt", ...header })
		.sign(privateKey);
	return { raw: `${jwt}~`, publicJwk: await jose.exportJWK(publicKey) };
}

describe("splitSdJwt", () => {
	it("splits an SD-JWT with no disclosures", () => {
		const split = splitSdJwt("a.b.c~");
		expect(split).toEqual({ issuerJwt: "a.b.c", rest: [] });
	});

	it("returns the disclosures when present", () => {
		expect(splitSdJwt("a.b.c~d1~d2~")?.rest).toEqual(["d1", "d2"]);
	});

	it("declines a plain JWT with no tilde", () => {
		expect(splitSdJwt("a.b.c")).toBeNull();
	});

	it("declines a non-string and a malformed issuer JWT", () => {
		expect(splitSdJwt(42)).toBeNull();
		expect(splitSdJwt("not-a-jwt~")).toBeNull();
	});
});

describe("decodeVcdm2SdJwt", () => {
	it("accepts a VCDM 2.0 credential in an SD-JWT", () => {
		expect(decodeVcdm2SdJwt(unsignedSdJwt(credentialBody))).not.toBeNull();
	});

	it("leaves a real SD-JWT VC alone, because it carries a vct", () => {
		expect(decodeVcdm2SdJwt(unsignedSdJwt({ vct: "https://example/vct", iss: ISSUER }))).toBeNull();
	});

	it("declines an SD-JWT whose payload is not a VCDM 2.0 credential", () => {
		expect(decodeVcdm2SdJwt(unsignedSdJwt({ hello: "world" }))).toBeNull();
	});

	it("declines a plain JWT and undecodable input", () => {
		expect(decodeVcdm2SdJwt(`${enc({ alg: "ES256" })}.${enc(credentialBody)}.sig`)).toBeNull();
		expect(decodeVcdm2SdJwt("%%%.%%%.sig~")).toBeNull();
	});
});

describe("detectCredentialFormat", () => {
	it("reports VCDM 2.0-as-SD-JWT rather than SD-JWT VC", () => {
		expect(detectCredentialFormat(unsignedSdJwt(credentialBody)))
			.toBe(VerifiableCredentialFormat.VCDM2_SDJWT);
	});

	it("still reports a credential carrying a vct as SD-JWT VC", () => {
		expect(detectCredentialFormat(unsignedSdJwt({ vct: "https://example/vct" })))
			.toBe(VerifiableCredentialFormat.VC_SDJWT);
	});
});

describe("presentation media type follows the credential", () => {
	it("names application/vc+sd-jwt for an SD-JWT credential", () => {
		const raw = unsignedSdJwt(credentialBody);
		expect(envelopedMediaTypeFor(raw)).toBe("application/vc+sd-jwt");
		const wrapped = wrapCredentialForPresentation(raw) as Record<string, unknown>;
		expect(wrapped.id).toBe(`data:application/vc+sd-jwt,${raw}`);
		expect(wrapped.type).toBe("EnvelopedVerifiableCredential");
	});

	it("names application/vc+jwt for an enveloped JOSE credential", () => {
		const raw = `${enc({ alg: "ES256", typ: "vc+jwt" })}.${enc(credentialBody)}.sig`;
		expect(envelopedMediaTypeFor(raw)).toBe("application/vc+jwt");
		expect((wrapCredentialForPresentation(raw) as any).id).toBe(`data:application/vc+jwt,${raw}`);
	});
});

describe("VCDM2SdJwtParser", () => {
	const parser = VCDM2SdJwtParser({ context: makeContext(), httpClient: offlineHttpClient });

	it("parses a credential the SD-JWT VC parser would have rejected for a missing vct", async () => {
		const result = await parser.parse({ rawCredential: unsignedSdJwt(credentialBody) });

		expect(result.success).toBe(true);
		if (!result.success) return;
		expect(result.value.metadata.credential.format).toBe(VerifiableCredentialFormat.VCDM2_SDJWT);
		expect(result.value.metadata.credential.type).toEqual(["VerifiableCredential", "StudentCardCredential"]);
		expect(result.value.metadata.issuer.id).toBe(ISSUER);
		expect(await result.value.metadata.credential.name()).toBe("StudentCardCredential");
	});

	it("prefers the JWT `iss` claim when the issuer provides one", async () => {
		const raw = unsignedSdJwt({ ...credentialBody, iss: "https://jwt-issuer.example" });
		const result = await parser.parse({ rawCredential: raw });
		expect(result.success).toBe(true);
		if (result.success) expect(result.value.metadata.issuer.id).toBe("https://jwt-issuer.example");
	});

	it("carries JWT validity claims into validityInfo", async () => {
		const raw = unsignedSdJwt({ ...credentialBody, exp: 1800000000, nbf: 1700000000, iat: 1650000000 });
		const result = await parser.parse({ rawCredential: raw });

		expect(result.success).toBe(true);
		if (!result.success) return;
		expect(result.value.validityInfo.validUntil).toEqual(new Date(1800000000 * 1000));
		expect(result.value.validityInfo.validFrom).toEqual(new Date(1700000000 * 1000));
		expect(result.value.validityInfo.signed).toEqual(new Date(1650000000 * 1000));
	});

	it("falls back to a generic name when only the base type is present", async () => {
		const raw = unsignedSdJwt({ ...credentialBody, type: ["VerifiableCredential"] });
		const result = await parser.parse({ rawCredential: raw });
		expect(result.success).toBe(true);
		if (result.success) expect(await result.value.metadata.credential.name()).toBe("Verifiable Credential");
	});

	it("defers on a real SD-JWT VC", async () => {
		const result = await parser.parse({ rawCredential: unsignedSdJwt({ vct: "https://example/vct" }) });
		expect(result.success).toBe(false);
		if (!result.success) expect(result.error).toBe(CredentialParsingError.UnsupportedFormat);
	});

	it("defers on a plain JWT", async () => {
		const raw = `${enc({ alg: "ES256", typ: "vc+jwt" })}.${enc(credentialBody)}.sig`;
		const result = await parser.parse({ rawCredential: raw });
		expect(result.success).toBe(false);
		if (!result.success) expect(result.error).toBe(CredentialParsingError.UnsupportedFormat);
	});

	it("reports a credential whose payload fails the VCDM 2.0 schema", async () => {
		// Structurally VCDM 2.0, but `issuer` is not a string or { id }.
		const raw = unsignedSdJwt({ ...credentialBody, issuer: 42 });
		const result = await parser.parse({ rawCredential: raw });
		expect(result.success).toBe(false);
		if (!result.success) expect(result.error).toBe(CredentialParsingError.InvalidVcdm2Credential);
	});

	it("reports an SD-JWT whose disclosures cannot be expanded", async () => {
		// A disclosure that is not valid base64url JSON makes expansion throw.
		const raw = `${unsignedSdJwt(credentialBody)}%%%~`;
		const result = await parser.parse({ rawCredential: raw });
		expect(result.success).toBe(false);
		if (!result.success) expect(result.error).toBe(CredentialParsingError.CouldNotParse);
	});

	it("applies issuer display and claim metadata when a configuration id is given", async () => {
		const metadata = {
			credential_issuer: ISSUER,
			credential_endpoint: `${ISSUER}/credential`,
			credential_configurations_supported: {
				StudentCardCredential: {
					format: "vc+sd-jwt",
					scope: "StudentCardCredential",
					credential_metadata: {
						display: [{ name: "Student Card", locale: "en-US", background_color: "#003366" }],
						claims: [{ path: ["given_name"], display: [{ name: "First name", locale: "en-US" }] }],
					},
				},
			},
		};
		const httpClient: HttpClient = {
			get: vi.fn(async (url: string) => (
				url.includes("/.well-known/openid-credential-issuer")
					? { status: 200, headers: {}, data: metadata }
					: { status: 404, headers: {}, data: null }
			)),
			post: vi.fn(),
		} as unknown as HttpClient;

		const withMetadata = VCDM2SdJwtParser({ context: makeContext(), httpClient });
		const result = await withMetadata.parse({
			rawCredential: unsignedSdJwt(credentialBody),
			credentialIssuer: { credentialIssuerIdentifier: ISSUER, credentialConfigurationId: "StudentCardCredential" },
		});

		expect(result.success).toBe(true);
		if (!result.success) return;
		expect(result.value.metadata.credential.TypeMetadata.claims?.length).toBeGreaterThan(0);
		expect(await result.value.metadata.credential.name(["en-US"])).toBe("Student Card");
		expect(await result.value.metadata.credential.rendering(["en-US"])).toMatchObject({ backgroundColor: "#003366" });
	});

	it("tolerates a configuration whose metadata has no claims", async () => {
		const metadata = {
			credential_issuer: ISSUER,
			credential_endpoint: `${ISSUER}/credential`,
			credential_configurations_supported: {
				StudentCardCredential: {
					format: "vc+sd-jwt",
					scope: "StudentCardCredential",
					credential_metadata: { display: [{ name: "Student Card", locale: "en-US" }] },
				},
			},
		};
		const httpClient: HttpClient = {
			get: vi.fn(async () => ({ status: 200, headers: {}, data: metadata })),
			post: vi.fn(),
		} as unknown as HttpClient;

		const result = await VCDM2SdJwtParser({ context: makeContext(), httpClient }).parse({
			rawCredential: unsignedSdJwt(credentialBody),
			credentialIssuer: { credentialIssuerIdentifier: ISSUER, credentialConfigurationId: "StudentCardCredential" },
		});
		expect(result.success).toBe(true);
		if (result.success) expect(result.value.metadata.credential.TypeMetadata.claims).toBeUndefined();
	});
});

describe("VCDM2SdJwtVerifier", () => {
	it("verifies the issuer signature over the issuer-signed JWT", async () => {
		const { raw, publicJwk } = await signedSdJwt();
		const verifier = VCDM2SdJwtVerifier({
			context: makeContext(), pkResolverEngine: resolverFor(publicJwk), httpClient: offlineHttpClient,
		});

		const result = await verifier.verify({ rawCredential: raw, opts: {} });
		expect(result.success).toBe(true);
		if (result.success) expect(result.value.holderPublicKey).toEqual({});
	});

	it("returns the holder key bound through cnf.jwk", async () => {
		const holder = { kty: "EC", crv: "P-256", x: "aa", y: "bb" };
		const { raw, publicJwk } = await signedSdJwt({ ...credentialBody, cnf: { jwk: holder } });
		const verifier = VCDM2SdJwtVerifier({
			context: makeContext(), pkResolverEngine: resolverFor(publicJwk), httpClient: offlineHttpClient,
		});

		const result = await verifier.verify({ rawCredential: raw, opts: {} });
		expect(result.success).toBe(true);
		if (result.success) expect(result.value.holderPublicKey).toEqual(holder);
	});

	it("does not start on a credential of another format", async () => {
		const verifier = VCDM2SdJwtVerifier({
			context: makeContext(), pkResolverEngine: resolverFor(null), httpClient: offlineHttpClient,
		});
		const result = await verifier.verify({ rawCredential: "not-a-credential", opts: {} });
		expect(result.success).toBe(false);
		if (!result.success) expect(result.error).toBe(CredentialVerificationError.VerificationProcessNotStarted);
	});

	it("reports an invalid signature", async () => {
		const { raw } = await signedSdJwt();
		const other = await jose.generateKeyPair("ES256", { extractable: true });
		const verifier = VCDM2SdJwtVerifier({
			context: makeContext(),
			pkResolverEngine: resolverFor(await jose.exportJWK(other.publicKey)),
			httpClient: offlineHttpClient,
		});

		const result = await verifier.verify({ rawCredential: raw, opts: {} });
		expect(result.success).toBe(false);
		if (!result.success) expect(result.error).toBe(CredentialVerificationError.InvalidSignature);
	});

	it("reports an expired credential distinctly", async () => {
		const { raw, publicJwk } = await signedSdJwt({ ...credentialBody, exp: 1000 });
		const verifier = VCDM2SdJwtVerifier({
			context: makeContext({ clockTolerance: 0 }),
			pkResolverEngine: resolverFor(publicJwk),
			httpClient: offlineHttpClient,
		});

		const result = await verifier.verify({ rawCredential: raw, opts: {} });
		expect(result.success).toBe(false);
		if (!result.success) expect(result.error).toBe(CredentialVerificationError.ExpiredCredential);
	});

	it("resolves by kid when the header names one", async () => {
		const { raw, publicJwk } = await signedSdJwt(credentialBody, { kid: `${ISSUER}#key-1` });
		const resolver = resolverFor(publicJwk);
		const verifier = VCDM2SdJwtVerifier({ context: makeContext(), pkResolverEngine: resolver, httpClient: offlineHttpClient });

		const result = await verifier.verify({ rawCredential: raw, opts: {} });
		expect(result.success).toBe(true);
		expect(resolver.resolve).toHaveBeenCalledWith({ identifier: `${ISSUER}#key-1` });
	});

	it("resolves by the JWT iss claim when present", async () => {
		const { raw, publicJwk } = await signedSdJwt({ ...credentialBody, iss: "https://jwt-issuer.example" });
		const resolver = resolverFor(publicJwk);
		const verifier = VCDM2SdJwtVerifier({ context: makeContext(), pkResolverEngine: resolver, httpClient: offlineHttpClient });

		const result = await verifier.verify({ rawCredential: raw, opts: {} });
		expect(result.success).toBe(true);
		expect(resolver.resolve).toHaveBeenCalledWith({ identifier: "https://jwt-issuer.example" });
	});

	it("falls back to the credential's issuer member when there is no iss", async () => {
		const { raw, publicJwk } = await signedSdJwt();
		const resolver = resolverFor(publicJwk);
		const verifier = VCDM2SdJwtVerifier({ context: makeContext(), pkResolverEngine: resolver, httpClient: offlineHttpClient });

		await verifier.verify({ rawCredential: raw, opts: {} });
		expect(resolver.resolve).toHaveBeenCalledWith({ identifier: ISSUER });
	});

	it("reports when there is nothing to resolve the key from", async () => {
		const raw = unsignedSdJwt({
			"@context": ["https://www.w3.org/ns/credentials/v2"],
			type: ["VerifiableCredential"],
			issuer: { name: "no id here" },
			credentialSubject: {},
		});
		const verifier = VCDM2SdJwtVerifier({
			context: makeContext(), pkResolverEngine: resolverFor(null), httpClient: offlineHttpClient,
		});

		const result = await verifier.verify({ rawCredential: raw, opts: {} });
		expect(result.success).toBe(false);
		if (!result.success) expect(result.error).toBe(CredentialVerificationError.CannotResolveIssuerPublicKey);
	});

	it("reports when the key cannot be resolved", async () => {
		const { raw } = await signedSdJwt();
		const verifier = VCDM2SdJwtVerifier({
			context: makeContext(), pkResolverEngine: resolverFor(null), httpClient: offlineHttpClient,
		});
		const result = await verifier.verify({ rawCredential: raw, opts: {} });
		expect(result.success).toBe(false);
		if (!result.success) expect(result.error).toBe(CredentialVerificationError.CannotResolveIssuerPublicKey);
	});

	it("reports when the resolved key cannot be imported", async () => {
		const { raw } = await signedSdJwt();
		const verifier = VCDM2SdJwtVerifier({
			context: makeContext(),
			pkResolverEngine: resolverFor({ kty: "EC", crv: "P-256", x: "!!", y: "!!" } as jose.JWK),
			httpClient: offlineHttpClient,
		});
		const result = await verifier.verify({ rawCredential: raw, opts: {} });
		expect(result.success).toBe(false);
		if (!result.success) expect(result.error).toBe(CredentialVerificationError.CannotImportIssuerPublicKey);
	});

	it("fails when the header has no alg", async () => {
		const raw = unsignedSdJwt(credentialBody, { typ: "vc+sd-jwt" });
		const verifier = VCDM2SdJwtVerifier({
			context: makeContext(), pkResolverEngine: resolverFor(null), httpClient: offlineHttpClient,
		});
		const result = await verifier.verify({ rawCredential: raw, opts: {} });
		expect(result.success).toBe(false);
		if (!result.success) expect(result.error).toBe(CredentialVerificationError.InvalidFormat);
	});

	describe("x5c handling", () => {
		async function signedWithCert() {
			const pkcs8 = Uint8Array.from(atob(TEST_PRIVATE_KEY_PKCS8_B64), (c) => c.charCodeAt(0));
			const privateKey = await subtle.importKey(
				"pkcs8", pkcs8.buffer as ArrayBuffer, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"],
			);
			const jwt = await new jose.SignJWT(credentialBody as jose.JWTPayload)
				.setProtectedHeader({ alg: "ES256", typ: "vc+sd-jwt", x5c: [TEST_CERT_DER_B64] })
				.sign(privateKey as unknown as jose.KeyLike);
			return `${jwt}~`;
		}

		it("verifies using the certificate in the header", async () => {
			const raw = await signedWithCert();
			const verifier = VCDM2SdJwtVerifier({
				context: makeContext(), pkResolverEngine: resolverFor(null), httpClient: offlineHttpClient,
			});
			const result = await verifier.verify({ rawCredential: raw, opts: {} });
			expect(result.success).toBe(true);
		});

		it("accepts a chain whose certificate is itself a trust anchor", async () => {
			const raw = await signedWithCert();
			const verifier = VCDM2SdJwtVerifier({
				context: makeContext({ delegateTrustToBackend: false, trustedCertificates: [TEST_CERT_PEM] }),
				pkResolverEngine: resolverFor(null),
				httpClient: offlineHttpClient,
			});
			const result = await verifier.verify({ rawCredential: raw, opts: {} });
			expect(result.success).toBe(true);
		});

		it("rejects a chain that reaches no configured anchor", async () => {
			const raw = await signedWithCert();
			const verifier = VCDM2SdJwtVerifier({
				context: makeContext({ delegateTrustToBackend: false, trustedCertificates: [UNRELATED_CERT_PEM] }),
				pkResolverEngine: resolverFor(null),
				httpClient: offlineHttpClient,
			});
			const result = await verifier.verify({ rawCredential: raw, opts: {} });
			expect(result.success).toBe(false);
			if (!result.success) expect(result.error).toBe(CredentialVerificationError.NotTrustedIssuer);
		});

		it("treats a malformed certificate as untrusted rather than throwing", async () => {
			const raw = unsignedSdJwt(credentialBody, { alg: "ES256", typ: "vc+sd-jwt", x5c: ["Zm9vYmFy"] });
			const verifier = VCDM2SdJwtVerifier({
				context: makeContext({ delegateTrustToBackend: false, trustedCertificates: [UNRELATED_CERT_PEM] }),
				pkResolverEngine: resolverFor(null),
				httpClient: offlineHttpClient,
			});
			const result = await verifier.verify({ rawCredential: raw, opts: {} });
			expect(result.success).toBe(false);
			if (!result.success) expect(result.error).toBe(CredentialVerificationError.NotTrustedIssuer);
		});

		it("reports a certificate that cannot be imported", async () => {
			const raw = unsignedSdJwt(credentialBody, { alg: "ES256", typ: "vc+sd-jwt", x5c: ["not-a-certificate"] });
			const verifier = VCDM2SdJwtVerifier({
				context: makeContext(), pkResolverEngine: resolverFor(null), httpClient: offlineHttpClient,
			});
			const result = await verifier.verify({ rawCredential: raw, opts: {} });
			expect(result.success).toBe(false);
			if (!result.success) expect(result.error).toBe(CredentialVerificationError.CannotImportIssuerPublicKey);
		});
	});
});

describe("holder binding and trust defaults for the SD-JWT form", () => {
	it("reads cnf.jwk out of the issuer-signed JWT", async () => {
		const { holderJwkFromCredential, holderIdFromCredential } = await import("../utils/vcdm2Presentation");
		const holder = { kty: "EC", crv: "P-256", x: "aa", y: "bb" };

		const bound = unsignedSdJwt({ ...credentialBody, cnf: { jwk: holder } });
		expect(holderJwkFromCredential(bound)).toEqual(holder);
		expect(holderIdFromCredential(bound)).toBe("did:example:subject");

		// No cnf: nothing to bind to, and the SD-JWT branch must not fall
		// through to the Data Integrity subject-id path.
		expect(holderJwkFromCredential(unsignedSdJwt(credentialBody))).toBeNull();
	});

	it("defaults to delegated trust when the context sets no trust fields", async () => {
		const pkcs8 = Uint8Array.from(atob(TEST_PRIVATE_KEY_PKCS8_B64), (c) => c.charCodeAt(0));
		const privateKey = await subtle.importKey(
			"pkcs8", pkcs8.buffer as ArrayBuffer, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"],
		);
		const jwt = await new jose.SignJWT(credentialBody as jose.JWTPayload)
			.setProtectedHeader({ alg: "ES256", typ: "vc+sd-jwt", x5c: [TEST_CERT_DER_B64] })
			.sign(privateKey as unknown as jose.KeyLike);

		const verifier = VCDM2SdJwtVerifier({
			// Neither delegateTrustToBackend nor trustedCertificates present.
			context: { clockTolerance: 60, lang: "en-US", subtle } as Context,
			pkResolverEngine: resolverFor(null),
			httpClient: offlineHttpClient,
		});

		const result = await verifier.verify({ rawCredential: `${jwt}~`, opts: {} });
		expect(result.success).toBe(true);
	});
});
