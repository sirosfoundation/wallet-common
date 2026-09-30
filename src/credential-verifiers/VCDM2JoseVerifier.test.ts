import { describe, expect, it, vi } from "vitest";
import * as jose from "jose";
import { VCDM2JoseVerifier } from "./VCDM2JoseVerifier";
import { CredentialVerificationError } from "../error";
import { TEST_CERT_DER_B64, TEST_CERT_PEM, TEST_PRIVATE_KEY_PKCS8_B64, UNRELATED_CERT_PEM } from "../testFixtures/vcdm2TestCertificate";
import {
	b64url as enc,
	b64ToBytes,
	bytesToB64Url,
	contextHttpClient,
	makeContext,
	makeResolver,
	offlineHttpClient,
	subtle,
	metadataHttpClient as serveMetadata,
} from "../testFixtures/vcdm2TestSupport";
import type { Context, PublicKeyResolverEngineI } from "../interfaces";

const ISSUER = "https://issuer.example";
const CONFIG_ID = "DiplomaCredential";

const issuerMetadata = {
	credential_issuer: ISSUER,
	credential_endpoint: `${ISSUER}/credential`,
	credential_configurations_supported: {
		[CONFIG_ID]: { format: "vc+jwt", scope: "diploma" },
	},
};

const metadataHttpClient = (metadata: unknown = issuerMetadata) => serveMetadata(metadata);

const credential = {
	"@context": ["https://www.w3.org/ns/credentials/v2"],
	type: ["VerifiableCredential"],
	issuer: "did:example:issuer",
	credentialSubject: { id: "did:example:subject", name: "Alice" },
};

const genericCredential = {
	"@context": ["https://www.w3.org/ns/credentials/v2"],
	type: ["VerifiableCredential"],
	issuer: "did:example:issuer",
	credentialSubject: { id: "did:example:subject" },
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

describe("VCDM2JoseVerifier", () => {
	it("verifies a correctly signed enveloped credential", async () => {
		const { jwt, publicJwk } = await signEnveloped();
		const verifier = VCDM2JoseVerifier({
			context: makeContext(),
			pkResolverEngine: makeResolver(publicJwk),
			httpClient,
		});

		const result = await verifier.verify({ rawCredential: jwt, opts: {} });
		expect(result.success).toBe(true);
	});

	it("returns the holder key from cnf.jwk when the issuer bound one", async () => {
		const holderJwk = { kty: "EC", crv: "P-256", x: "aa", y: "bb" };
		const { jwt, publicJwk } = await signEnveloped({ cnf: { jwk: holderJwk } });
		const verifier = VCDM2JoseVerifier({
			context: makeContext(),
			pkResolverEngine: makeResolver(publicJwk),
			httpClient,
		});

		const result = await verifier.verify({ rawCredential: jwt, opts: {} });
		expect(result.success).toBe(true);
		if (result.success) expect(result.value.holderPublicKey).toEqual(holderJwk);
	});

	it("returns an empty holder key when there is no cnf binding", async () => {
		const { jwt, publicJwk } = await signEnveloped();
		const verifier = VCDM2JoseVerifier({
			context: makeContext(),
			pkResolverEngine: makeResolver(publicJwk),
			httpClient,
		});

		const result = await verifier.verify({ rawCredential: jwt, opts: {} });
		expect(result.success).toBe(true);
		if (result.success) expect(result.value.holderPublicKey).toEqual({});
	});

	it("does not start on a credential that is not an enveloped VCDM 2.0 one", async () => {
		const verifier = VCDM2JoseVerifier({
			context: makeContext(),
			pkResolverEngine: makeResolver(null),
			httpClient,
		});

		const result = await verifier.verify({ rawCredential: "not-a-jwt", opts: {} });
		expect(result.success).toBe(false);
		if (!result.success) expect(result.error).toBe(CredentialVerificationError.VerificationProcessNotStarted);
	});

	it("reports an invalid signature when the key does not match", async () => {
		const { jwt } = await signEnveloped();
		const other = await jose.generateKeyPair("ES256", { extractable: true });
		const verifier = VCDM2JoseVerifier({
			context: makeContext(),
			pkResolverEngine: makeResolver(await jose.exportJWK(other.publicKey)),
			httpClient,
		});

		const result = await verifier.verify({ rawCredential: jwt, opts: {} });
		expect(result.success).toBe(false);
		if (!result.success) expect(result.error).toBe(CredentialVerificationError.InvalidSignature);
	});

	it("reports an expired credential distinctly from a bad signature", async () => {
		const { publicKey, privateKey } = await jose.generateKeyPair("ES256", { extractable: true });
		const jwt = await new jose.SignJWT({ ...credentialBody, exp: 1000 })
			.setProtectedHeader({ alg: "ES256", typ: "vc+jwt" })
			.sign(privateKey);

		const verifier = VCDM2JoseVerifier({
			context: makeContext({ clockTolerance: 0 }),
			pkResolverEngine: makeResolver(await jose.exportJWK(publicKey)),
			httpClient,
		});

		const result = await verifier.verify({ rawCredential: jwt, opts: {} });
		expect(result.success).toBe(false);
		if (!result.success) expect(result.error).toBe(CredentialVerificationError.ExpiredCredential);
	});

	it("reports when the issuer key cannot be resolved", async () => {
		const { jwt } = await signEnveloped();
		const verifier = VCDM2JoseVerifier({
			context: makeContext(),
			pkResolverEngine: makeResolver(null),
			httpClient,
		});

		const result = await verifier.verify({ rawCredential: jwt, opts: {} });
		expect(result.success).toBe(false);
		// An issuer object without an `id` is not a valid VCDM 2.0 credential,
		// so schema validation rejects it before key resolution is attempted.
		if (!result.success) expect(result.error).toBe(CredentialVerificationError.CannotResolveIssuerPublicKey);
	});

	it("reports when the resolved key cannot be imported", async () => {
		const { jwt } = await signEnveloped();
		const verifier = VCDM2JoseVerifier({
			context: makeContext(),
			pkResolverEngine: makeResolver({ kty: "EC", crv: "P-256", x: "!!", y: "!!" } as jose.JWK),
			httpClient,
		});

		const result = await verifier.verify({ rawCredential: jwt, opts: {} });
		expect(result.success).toBe(false);
		if (!result.success) expect(result.error).toBe(CredentialVerificationError.CannotImportIssuerPublicKey);
	});

	it("resolves by kid when the header names one", async () => {
		const { publicKey, privateKey } = await jose.generateKeyPair("ES256", { extractable: true });
		const jwt = await new jose.SignJWT(credentialBody)
			.setProtectedHeader({ alg: "ES256", typ: "vc+jwt", kid: "did:example:issuer#key-1" })
			.sign(privateKey);

		const resolver = makeResolver(await jose.exportJWK(publicKey));
		const verifier = VCDM2JoseVerifier({ context: makeContext(), pkResolverEngine: resolver, httpClient });

		const result = await verifier.verify({ rawCredential: jwt, opts: {} });
		expect(result.success).toBe(true);
		expect(resolver.resolve).toHaveBeenCalledWith({ identifier: "did:example:issuer#key-1" });
	});

	it("rejects a malformed issuer before attempting key resolution", async () => {
		const { privateKey } = await jose.generateKeyPair("ES256", { extractable: true });
		const jwt = await new jose.SignJWT({
			"@context": ["https://www.w3.org/ns/credentials/v2"],
			type: ["VerifiableCredential"],
			issuer: { name: "no id here" },
			credentialSubject: {},
		})
			.setProtectedHeader({ alg: "ES256", typ: "vc+jwt" })
			.sign(privateKey);

		const verifier = VCDM2JoseVerifier({
			context: makeContext(),
			pkResolverEngine: makeResolver(null),
			httpClient,
		});

		const result = await verifier.verify({ rawCredential: jwt, opts: {} });
		expect(result.success).toBe(false);
		// An issuer object without an `id` is not a valid VCDM 2.0 credential,
		// so schema validation rejects it before key resolution is attempted.
		if (!result.success) expect(result.error).toBe(CredentialVerificationError.InvalidFormat);
	});

	it("fails when the header has no alg", async () => {
		// Hand-built so the header genuinely lacks `alg`.
		const enc = (value: object) => {
			const bytes = new TextEncoder().encode(JSON.stringify(value));
			let binary = "";
			for (const b of bytes) binary += String.fromCharCode(b);
			return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
		};
		const raw = `${enc({ typ: "vc+jwt" })}.${enc(credentialBody)}.sig`;

		const verifier = VCDM2JoseVerifier({
			context: makeContext(),
			pkResolverEngine: makeResolver(null),
			httpClient,
		});

		const result = await verifier.verify({ rawCredential: raw, opts: {} });
		expect(result.success).toBe(false);
		if (!result.success) expect(result.error).toBe(CredentialVerificationError.InvalidFormat);
	});
});

describe("VCDM2JoseVerifier x5c handling", () => {
	function resolver(): PublicKeyResolverEngineI {
		return {
			register: vi.fn(),
			resolve: vi.fn(async () => ({ success: false as const, error: "CannotResolvePublicKey" as any })),
		} as unknown as PublicKeyResolverEngineI;
	}

	async function signedWithX5c(x5c: string[]) {
		const { privateKey } = await jose.generateKeyPair("ES256", { extractable: true });
		return new jose.SignJWT(credentialBody)
			.setProtectedHeader({ alg: "ES256", typ: "vc+jwt", x5c })
			.sign(privateKey);
	}

	it("reports a certificate that cannot be imported", async () => {
		const jwt = await signedWithX5c(["not-a-certificate"]);
		const verifier = VCDM2JoseVerifier({
			context: makeContext(),
			pkResolverEngine: resolver(),
			httpClient: metadataHttpClient(),
		});

		const result = await verifier.verify({ rawCredential: jwt, opts: {} });
		expect(result.success).toBe(false);
		if (!result.success) expect(result.error).toBe(CredentialVerificationError.CannotImportIssuerPublicKey);
	});

	it("rejects an untrusted chain when trust is evaluated locally", async () => {
		const jwt = await signedWithX5c(["Zm9vYmFy"]);
		const verifier = VCDM2JoseVerifier({
			context: makeContext({
				delegateTrustToBackend: false,
				trustedCertificates: ["-----BEGIN CERTIFICATE-----\nc29tZXRoaW5nZWxzZQ==\n-----END CERTIFICATE-----"],
			}),
			pkResolverEngine: resolver(),
			httpClient: metadataHttpClient(),
		});

		const result = await verifier.verify({ rawCredential: jwt, opts: {} });
		expect(result.success).toBe(false);
		if (!result.success) expect(result.error).toBe(CredentialVerificationError.NotTrustedIssuer);
	});

	it("refuses an x5c chain when local trust has no anchors configured", async () => {
		// Previously the whole trust block was skipped when the anchor list was
		// empty, so any issuer presenting a chain was accepted and the only
		// remaining hurdle was whether the certificate parsed. Evaluating trust
		// locally with nothing to trust against cannot establish anything, so
		// it now fails instead. Raised in review by @smncd.
		const jwt = await signedWithX5c(["not-a-certificate"]);
		const verifier = VCDM2JoseVerifier({
			context: makeContext({ delegateTrustToBackend: false, trustedCertificates: [] }),
			pkResolverEngine: resolver(),
			httpClient: metadataHttpClient(),
		});

		const result = await verifier.verify({ rawCredential: jwt, opts: {} });
		expect(result.success).toBe(false);
		if (!result.success) expect(result.error).toBe(CredentialVerificationError.NotTrustedIssuer);
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

/**
 * The detector accepts a token on its `typ` header or a three-member payload
 * shape, neither of which is the VCDM 2.0 schema. A validly signed token that
 * clears those but violates the schema must not be reported as verified.
 */
describe("VCDM2JoseVerifier payload validation", () => {
	it("refuses a signed vc+jwt whose payload is not a VCDM 2.0 credential", async () => {
		const { privateKey, publicKey } = await jose.generateKeyPair("ES256", { extractable: true });

		// Correct typ, correct signature, but no credentialSubject.
		const jwt = await new jose.SignJWT({
			"@context": ["https://www.w3.org/ns/credentials/v2"],
			type: ["VerifiableCredential"],
			issuer: "did:example:issuer",
		})
			.setProtectedHeader({ alg: "ES256", typ: "vc+jwt" })
			.sign(privateKey);

		const verifier = VCDM2JoseVerifier({
			context: makeContext(),
			pkResolverEngine: makeResolver(await jose.exportJWK(publicKey)),
			httpClient,
		});

		const result = await verifier.verify({ rawCredential: jwt, opts: {} });
		expect(result.success).toBe(false);
		if (!result.success) expect(result.error).toBe(CredentialVerificationError.InvalidFormat);
	});
});
