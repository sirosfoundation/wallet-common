import { describe, expect, it, vi } from "vitest";
import * as jose from "jose";
import { VCDM2SdJwtParser } from "./VCDM2SdJwtParser";
import { ParsingEngine } from "../ParsingEngine";
import { SDJWTVCParser } from "./SDJWTVCParser";
import { MsoMdocParser } from "./MsoMdocParser";
import { JWTVCJSONParser } from "./JWTVCJSONParser";
import { CredentialParsingError } from "../error";
import { VerifiableCredentialFormat } from "../types";
import { detectCredentialFormat } from "../utils/detectCredentialFormat";
import { decodeVcdm2SdJwt } from "../utils/vcdm2";
import { MBOB_ACADEMIC_ENROLLMENT, EPI_EDUID } from "../testFixtures/realCredentials";
import {
	b64url as enc,
	makeContext,
	makeResolver,
	offlineHttpClient,
	subtle,
	unsignedSdJwt,
} from "../testFixtures/vcdm2TestSupport";
import type { Context } from "../interfaces";

const context = makeContext();

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

const resolverFor = makeResolver;

/** A genuinely signed SD-JWT over this file's credential body. */
async function signedSdJwt(payload: object = credentialBody, header: Record<string, unknown> = {}) {
	const { publicKey, privateKey } = await jose.generateKeyPair("ES256", { extractable: true });
	const jwt = await new jose.SignJWT(payload as jose.JWTPayload)
		.setProtectedHeader({ alg: "ES256", typ: "vc+sd-jwt", ...header })
		.sign(privateKey);
	return { raw: `${jwt}~`, publicJwk: await jose.exportJWK(publicKey) };
}

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

describe("mbob AcademicEnrollmentCredential — VCDM 2.0 carried in an SD-JWT", () => {
	it("is recognised as VCDM 2.0 rather than SD-JWT VC", () => {
		expect(detectCredentialFormat(MBOB_ACADEMIC_ENROLLMENT))
			.toBe(VerifiableCredentialFormat.VCDM2_SDJWT);
	});

	it("is rejected by the SD-JWT VC parser for the missing vct — the reported bug", async () => {
		// Without the VCDM 2.0 parser in front, this is exactly what users hit:
		// SDJWTVCParser claims the credential and fails its payload schema,
		// whose only unmet requirement is `vct`.
		const engine = ParsingEngine();
		engine.register(SDJWTVCParser({ context, httpClient: offlineHttpClient }));
		engine.register(MsoMdocParser({ context, httpClient: offlineHttpClient }));
		engine.register(JWTVCJSONParser({ context, httpClient: offlineHttpClient }));

		const result = await engine.parse({ rawCredential: MBOB_ACADEMIC_ENROLLMENT });
		expect(result.success).toBe(false);
		if (!result.success) expect(result.error).toBe(CredentialParsingError.InvalidSdJwtVcPayload);
	});

	it("parses once the VCDM 2.0 parser is registered ahead of it", async () => {
		const engine = ParsingEngine();
		engine.register(VCDM2SdJwtParser({ context, httpClient: offlineHttpClient }));
		engine.register(SDJWTVCParser({ context, httpClient: offlineHttpClient }));
		engine.register(MsoMdocParser({ context, httpClient: offlineHttpClient }));
		engine.register(JWTVCJSONParser({ context, httpClient: offlineHttpClient }));

		const result = await engine.parse({ rawCredential: MBOB_ACADEMIC_ENROLLMENT });

		expect(result.success).toBe(true);
		if (!result.success) return;

		const credential = result.value.metadata.credential;
		expect(credential.format).toBe(VerifiableCredentialFormat.VCDM2_SDJWT);
		expect(credential.type).toEqual(["VerifiableCredential", "AcademicEnrollmentCredential"]);

		// The issuer is an object here — `{ id, name, description }` — so the
		// display name comes from the credential rather than falling back to
		// the bare DID.
		expect(result.value.metadata.issuer.id).toBe("did:web:mbob.issuer.dev.eduwallet.nl");
		expect(result.value.metadata.issuer.name).toBe("MBO Beek");

		// VCDM 2.0 dates, not JWT `nbf`/`exp`.
		expect(result.value.validityInfo.validFrom).toEqual(new Date("2026-09-08T12:31:02Z"));

		const claims = result.value.signedClaims as Record<string, unknown>;
		expect(claims["@context"]).toEqual(["https://www.w3.org/ns/credentials/v2"]);
		expect(claims.vct).toBeUndefined();
		expect((claims.credentialSubject as Record<string, unknown>).institutionBRINCode).toBe("AK0092");
	});
});

describe("epi eduID — a genuine SD-JWT VC", () => {
	it("is left to the SD-JWT VC parser, because it carries a vct", () => {
		// The guard that keeps the VCDM 2.0 parser, which is registered first,
		// from swallowing ordinary SD-JWT VCs.
		expect(decodeVcdm2SdJwt(EPI_EDUID)).toBeNull();
		expect(detectCredentialFormat(EPI_EDUID)).toBe(VerifiableCredentialFormat.DC_SDJWT);
	});

	it("is declined by the VCDM 2.0 parser", async () => {
		const parser = VCDM2SdJwtParser({ context, httpClient: offlineHttpClient });
		const result = await parser.parse({ rawCredential: EPI_EDUID });

		expect(result.success).toBe(false);
		if (!result.success) expect(result.error).toBe(CredentialParsingError.UnsupportedFormat);
	});
});
