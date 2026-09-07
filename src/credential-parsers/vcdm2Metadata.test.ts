import { describe, expect, it, vi } from "vitest";
import * as jose from "jose";
import { VCDM2JoseParser } from "./VCDM2JoseParser";
import { VCDM2LdpParser } from "./VCDM2LdpParser";
import { VCDM2JoseVerifier } from "../credential-verifiers/VCDM2JoseVerifier";
import { VCDM2LdpVerifier } from "../credential-verifiers/VCDM2LdpVerifier";
import { CredentialParsingError, CredentialVerificationError } from "../error";
import type { Context, HttpClient, PublicKeyResolverEngineI } from "../interfaces";

const subtle = globalThis.crypto.subtle;

const ISSUER = "https://issuer.example";
const CONFIG_ID = "diploma";

const credentialBody = {
	"@context": ["https://www.w3.org/ns/credentials/v2"],
	type: ["VerifiableCredential", "DiplomaCredential"],
	issuer: ISSUER,
	credentialSubject: { id: "did:example:subject", degree: "BSc" },
};

/** Issuer metadata carrying both display and claim metadata. */
const issuerMetadata = {
	credential_issuer: ISSUER,
	credential_endpoint: `${ISSUER}/credential`,
	credential_configurations_supported: {
		[CONFIG_ID]: {
			format: "vc+jwt",
			scope: "diploma",
			credential_metadata: {
				display: [{
					name: "Diploma",
					locale: "en-US",
					background_color: "#ffffff",
					text_color: "#000000",
				}],
				claims: [
					{ path: ["degree"], display: [{ name: "Degree", locale: "en-US" }] },
				],
			},
		},
	},
};

function metadataHttpClient(metadata: unknown = issuerMetadata): HttpClient {
	return {
		get: vi.fn(async (url: string) => (
			url.includes("/.well-known/openid-credential-issuer")
				? { status: 200, headers: {}, data: metadata }
				: { status: 404, headers: {}, data: null }
		)),
		post: vi.fn(),
	} as unknown as HttpClient;
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

function enc(value: object): string {
	const bytes = new TextEncoder().encode(JSON.stringify(value));
	let binary = "";
	for (const b of bytes) binary += String.fromCharCode(b);
	return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

describe("VCDM2JoseParser with issuer metadata", () => {
	const raw = `${enc({ alg: "ES256", typ: "vc+jwt" })}.${enc(credentialBody)}.sig`;

	it("applies display and claim metadata from the issuer's configuration", async () => {
		const parser = VCDM2JoseParser({ context: makeContext(), httpClient: metadataHttpClient() });

		const result = await parser.parse({
			rawCredential: raw,
			credentialIssuer: { credentialIssuerIdentifier: ISSUER, credentialConfigurationId: CONFIG_ID },
		});

		expect(result.success).toBe(true);
		if (!result.success) return;

		const credential = result.value.metadata.credential;
		expect(credential.TypeMetadata.claims?.length).toBeGreaterThan(0);
		expect(await credential.name(["en-US"])).toBe("Diploma");
		expect(await credential.rendering(["en-US"])).toMatchObject({ backgroundColor: "#ffffff" });
	});

	it("falls back to the credential's own type when no configuration id is given", async () => {
		const parser = VCDM2JoseParser({ context: makeContext(), httpClient: metadataHttpClient() });

		const result = await parser.parse({ rawCredential: raw });
		expect(result.success).toBe(true);
		if (!result.success) return;
		expect(await result.value.metadata.credential.name(["en-US"])).toBe("DiplomaCredential");
	});

	it("tolerates a configuration whose metadata has no claims", async () => {
		const withoutClaims = {
			...issuerMetadata,
			credential_configurations_supported: {
				[CONFIG_ID]: { format: "vc+jwt", scope: "diploma", credential_metadata: { display: [{ name: "Diploma", locale: "en-US" }] } },
			},
		};
		const parser = VCDM2JoseParser({ context: makeContext(), httpClient: metadataHttpClient(withoutClaims) });

		const result = await parser.parse({
			rawCredential: raw,
			credentialIssuer: { credentialIssuerIdentifier: ISSUER, credentialConfigurationId: CONFIG_ID },
		});
		expect(result.success).toBe(true);
		if (result.success) expect(result.value.metadata.credential.TypeMetadata.claims).toBeUndefined();
	});

	it("reports a header without an alg as unparseable", async () => {
		const parser = VCDM2JoseParser({ context: makeContext(), httpClient: metadataHttpClient() });
		const noAlg = `${enc({ typ: "vc+jwt" })}.${enc(credentialBody)}.sig`;

		const result = await parser.parse({ rawCredential: noAlg });
		expect(result.success).toBe(false);
		if (!result.success) expect(result.error).toBe(CredentialParsingError.CouldNotParse);
	});

	it("reports a payload that is not a valid VCDM 2.0 credential", async () => {
		const parser = VCDM2JoseParser({ context: makeContext(), httpClient: metadataHttpClient() });
		// `typ` claims VCDM 2.0, but the payload has no context/type/issuer.
		const bad = `${enc({ alg: "ES256", typ: "vc+jwt" })}.${enc({ hello: "world" })}.sig`;

		const result = await parser.parse({ rawCredential: bad });
		expect(result.success).toBe(false);
		if (!result.success) expect(result.error).toBe(CredentialParsingError.InvalidVcdm2Credential);
	});
});

describe("VCDM2LdpParser with issuer metadata", () => {
	it("applies display and claim metadata", async () => {
		const parser = VCDM2LdpParser({ context: makeContext(), httpClient: metadataHttpClient() });

		const result = await parser.parse({
			rawCredential: credentialBody,
			credentialIssuer: { credentialIssuerIdentifier: ISSUER, credentialConfigurationId: CONFIG_ID },
		});

		expect(result.success).toBe(true);
		if (!result.success) return;
		expect(result.value.metadata.credential.TypeMetadata.claims?.length).toBeGreaterThan(0);
		expect(await result.value.metadata.credential.name(["en-US"])).toBe("Diploma");
	});

	it("tolerates a configuration whose metadata has no claims", async () => {
		const withoutClaims = {
			...issuerMetadata,
			credential_configurations_supported: {
				[CONFIG_ID]: { format: "ldp_vc", scope: "diploma", credential_metadata: { display: [{ name: "Diploma", locale: "en-US" }] } },
			},
		};
		const parser = VCDM2LdpParser({ context: makeContext(), httpClient: metadataHttpClient(withoutClaims) });

		const result = await parser.parse({
			rawCredential: credentialBody,
			credentialIssuer: { credentialIssuerIdentifier: ISSUER, credentialConfigurationId: CONFIG_ID },
		});
		expect(result.success).toBe(true);
	});

	it("reports a credential that is structurally VCDM 2.0 but fails the schema", async () => {
		const parser = VCDM2LdpParser({ context: makeContext(), httpClient: metadataHttpClient() });

		const result = await parser.parse({
			rawCredential: {
				"@context": ["https://www.w3.org/ns/credentials/v2"],
				type: ["VerifiableCredential"],
				issuer: 42,
				credentialSubject: {},
			},
		});

		expect(result.success).toBe(false);
		if (!result.success) expect(result.error).toBe(CredentialParsingError.InvalidVcdm2Credential);
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

	it("skips local chain validation when no trust anchors are configured", async () => {
		const jwt = await signedWithX5c(["not-a-certificate"]);
		const verifier = VCDM2JoseVerifier({
			context: makeContext({ delegateTrustToBackend: false, trustedCertificates: [] }),
			pkResolverEngine: resolver(),
			httpClient: metadataHttpClient(),
		});

		// Reaches the import step rather than failing on trust.
		const result = await verifier.verify({ rawCredential: jwt, opts: {} });
		expect(result.success).toBe(false);
		if (!result.success) expect(result.error).toBe(CredentialVerificationError.CannotImportIssuerPublicKey);
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
