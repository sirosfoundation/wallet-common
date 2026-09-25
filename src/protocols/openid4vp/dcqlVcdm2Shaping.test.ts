import { describe, expect, it } from "vitest";
import { DcqlQuery } from "dcql";
import { MBOB_ACADEMIC_ENROLLMENT } from "../../testFixtures/realCredentials";
import { decodeVcdm2SdJwt, toTypeArray } from "../../utils/vcdm2";

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

	it("the credential really has no vct to match on", () => {
		expect(claims.vct).toBeUndefined();
		expect(toTypeArray(claims.type)).toContain("AcademicEnrollmentCredential");
	});

	it("shaped the old way, it matches nothing", () => {
		const shapedTheOldWay = {
			credential_format: "vcdm2+sd-jwt", // internal discriminator
			vct: claims.vct,                   // undefined
			claims,
			cryptographic_holder_binding: true,
		};

		const parsed = DcqlQuery.parse(query as never);
		const result = DcqlQuery.query(parsed, [shapedTheOldWay] as never);
		expect(result.credential_matches["enrollment"]?.success).not.toBe(true);
	});

	it("shaped as a W3C credential, it matches", () => {
		const shaped = {
			credential_format: "vc+sd-jwt",          // the wire value
			type: toTypeArray(claims.type),          // identified by type, not vct
			claims,
			cryptographic_holder_binding: true,
		};

		const parsed = DcqlQuery.parse(query as never);
		const result = DcqlQuery.query(parsed, [shaped] as never);

		const match = result.credential_matches["enrollment"];
		expect(match?.success).toBe(true);
	});
});
