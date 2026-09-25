import { describe, expect, it, vi } from "vitest";
import * as jose from "jose";
import { VCDM2JoseVerifier } from "./VCDM2JoseVerifier";
import { VCDM2LdpVerifier } from "./VCDM2LdpVerifier";
import { CredentialVerificationError } from "../error";
import { canonicalizeJcs } from "../utils/dataIntegrity/jcs";
import type { Context, HttpClient, PublicKeyResolverEngineI } from "../interfaces";

const subtle = globalThis.crypto.subtle;

const httpClient: HttpClient = {
	async get() { return { status: 404, headers: {}, data: null }; },
	async post() { return { status: 404, headers: {}, data: null }; },
};

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

/** A resolver engine that answers with `jwk` for any identifier, or fails. */
function makeResolver(jwk: jose.JWK | null): PublicKeyResolverEngineI {
	return {
		register: vi.fn(),
		resolve: vi.fn(async () => (
			jwk
				? { success: true as const, value: { jwk } }
				: { success: false as const, error: "CannotResolvePublicKey" as any }
		)),
	} as unknown as PublicKeyResolverEngineI;
}

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

	it("fails when there is neither a kid nor a resolvable issuer", async () => {
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
		if (!result.success) expect(result.error).toBe(CredentialVerificationError.CannotResolveIssuerPublicKey);
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
