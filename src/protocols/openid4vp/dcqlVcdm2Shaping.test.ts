import { describe, expect, it } from "vitest";
import { DcqlQuery } from "dcql";
import { MBOB_ACADEMIC_ENROLLMENT } from "../../testFixtures/realCredentials";
import { decodeVcdm2SdJwt, isVcdm2Credential, toTypeArray } from "../../utils/vcdm2";

/**
 * A real mbob credential has no `vct` and is identified by its `type` array,
 * so DCQL models it as a W3C credential rather than an SD-JWT VC. Shaping it
 * the SD-JWT VC way -- an undefined `vct`, and the internal `vcdm2+sd-jwt`
 * discriminator as the format -- cannot match any query, which surfaced in the
 * wallet as a failure during credential selection.
 */
describe("DCQL shaping for a VCDM 2.0 credential carried in an SD-JWT", () => {
	const decoded = decodeVcdm2SdJwt(MBOB_ACADEMIC_ENROLLMENT);
	const claims = decoded!.payload as Record<string, unknown>;

	// What a verifier asking for this credential sends.
	const query = {
		credentials: [{
			id: "enrollment",
			format: "vc+sd-jwt",
			meta: { type_values: [["AcademicEnrollmentCredential"]] },
		}],
	};

	const runQuery = (shaped: unknown) => {
		const parsed = DcqlQuery.parse(query as never);
		return DcqlQuery.query(parsed, [shaped] as never).credential_matches["enrollment"];
	};

	it("the credential really has no vct to match on", () => {
		expect(claims.vct).toBeUndefined();
		expect(toTypeArray(claims.type)).toContain("AcademicEnrollmentCredential");
	});

	it("shaped the old way, it matches nothing", () => {
		expect(runQuery({
			credential_format: "vcdm2+sd-jwt", // internal discriminator
			vct: claims.vct,                   // undefined
			claims,
			cryptographic_holder_binding: true,
		})?.success).not.toBe(true);
	});

	it("shaped as a W3C credential, it matches", () => {
		expect(runQuery({
			credential_format: "vc+sd-jwt",
			type: toTypeArray(claims.type),
			claims,
			cryptographic_holder_binding: true,
		})?.success).toBe(true);
	});

	/**
	 * The wallet records the format the *issuer advertised*, and this
	 * credential is advertised as `vc+sd-jwt` -- the identifier legacy SD-JWT
	 * VC also uses. So the stored label cannot decide the shaping; only the
	 * payload can. This is the case that actually failed against the proeftuin.
	 */
	it("is recognised from its payload, not its stored format label", () => {
		expect(isVcdm2Credential(claims)).toBe(true);
		expect(claims.vct).toBeUndefined();
	});

	it("a genuine SD-JWT VC is not mistaken for VCDM 2.0", () => {
		// The guard has to hold in both directions: an SD-JWT VC carries a
		// vct and must keep its vct-based shaping.
		expect(isVcdm2Credential({ vct: "urn:eduid", iss: "https://example" })).toBe(false);
	});
});
