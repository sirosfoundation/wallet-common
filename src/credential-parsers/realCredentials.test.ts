import { describe, expect, it } from "vitest";
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
import type { Context, HttpClient } from "../interfaces";

/**
 * Regression tests against credentials actually issued by the eduwallet dev
 * issuers, rather than reconstructions.
 *
 * The HTTP client is stubbed so these stay hermetic: issuer metadata is a
 * nice-to-have that degrades to a warning, and none of the behaviour being
 * asserted depends on it.
 */
const offlineHttpClient: HttpClient = {
	async get() { return { status: 404, headers: {}, data: null }; },
	async post() { return { status: 404, headers: {}, data: null }; },
};

const context = {
	clockTolerance: 60,
	lang: "en-US",
	subtle: globalThis.crypto.subtle,
} as Context;

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
