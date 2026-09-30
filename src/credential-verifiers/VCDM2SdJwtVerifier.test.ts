import { describe, expect, it, vi } from "vitest";
import * as jose from "jose";
import { VCDM2SdJwtVerifier } from "./VCDM2SdJwtVerifier";
import { CredentialVerificationError } from "../error";
import { TEST_CERT_DER_B64, TEST_CERT_PEM, TEST_PRIVATE_KEY_PKCS8_B64, UNRELATED_CERT_PEM } from "../testFixtures/vcdm2TestCertificate";
import {
	b64url as enc,
	makeContext,
	makeResolver,
	offlineHttpClient,
	subtle,
	unsignedSdJwt,
} from "../testFixtures/vcdm2TestSupport";
import type { Context } from "../interfaces";

const httpClient = offlineHttpClient;

const ISSUER = "https://mbob.issuer.dev.eduwallet.nl";

const credentialBody = {
	"@context": ["https://www.w3.org/ns/credentials/v2"],
	type: ["VerifiableCredential", "StudentCardCredential"],
	issuer: ISSUER,
	credentialSubject: { id: "did:example:subject", given_name: "Alice" },
};

const resolverFor = makeResolver;

async function signedSdJwt(payload: object = credentialBody, header: Record<string, unknown> = {}) {
	const { publicKey, privateKey } = await jose.generateKeyPair("ES256", { extractable: true });
	const jwt = await new jose.SignJWT(payload as jose.JWTPayload)
		.setProtectedHeader({ alg: "ES256", typ: "vc+sd-jwt", ...header })
		.sign(privateKey);
	return { raw: `${jwt}~`, publicJwk: await jose.exportJWK(publicKey) };
}

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

	it("rejects a malformed issuer before attempting key resolution", async () => {
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
		// An issuer object without an `id` is not a valid VCDM 2.0 credential,
		// so schema validation rejects it before key resolution is attempted.
		if (!result.success) expect(result.error).toBe(CredentialVerificationError.InvalidFormat);
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

/**
 * The detector accepts a token on its `typ` header or a three-member payload
 * shape, neither of which is the VCDM 2.0 schema. A validly signed token that
 * clears those but violates the schema must not be reported as verified.
 */
describe("VCDM2SdJwtVerifier payload validation", () => {
	it("refuses a signed vc+sd-jwt whose payload is not a VCDM 2.0 credential", async () => {
		const { privateKey, publicKey } = await jose.generateKeyPair("ES256", { extractable: true });

		const issuerJwt = await new jose.SignJWT({
			"@context": ["https://www.w3.org/ns/credentials/v2"],
			type: ["VerifiableCredential"],
			issuer: "did:example:issuer",
		})
			.setProtectedHeader({ alg: "ES256", typ: "vc+sd-jwt" })
			.sign(privateKey);

		const verifier = VCDM2SdJwtVerifier({
			context: makeContext(),
			pkResolverEngine: makeResolver(await jose.exportJWK(publicKey)),
			httpClient,
		});

		const result = await verifier.verify({ rawCredential: `${issuerJwt}~`, opts: {} });
		expect(result.success).toBe(false);
		if (!result.success) expect(result.error).toBe(CredentialVerificationError.InvalidFormat);
	});
});
