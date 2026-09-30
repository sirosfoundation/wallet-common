import { describe, expect, it } from "vitest";
import { resolveVcdm2IssuerPublicKey } from "./vcdm2IssuerKey";
import { CredentialVerificationError } from "../error";
import { makeContext, makeResolver } from "../testFixtures/vcdm2TestSupport";

describe("resolveVcdm2IssuerPublicKey", () => {
	it("refuses an x5c chain when local trust has no anchors configured", async () => {
		// Evaluating trust locally with nothing to trust against cannot
		// establish anything; skipping the check would accept any issuer that
		// presents a chain. Raised in review by @smncd.
		const result = await resolveVcdm2IssuerPublicKey(
			{
				context: makeContext({ delegateTrustToBackend: false, trustedCertificates: [] }),
				pkResolverEngine: makeResolver(null),
			},
			{ alg: "ES256", x5c: ["Zm9v"] },
			{},
		);

		expect(result.success).toBe(false);
		if (!result.success) expect(result.error).toBe(CredentialVerificationError.NotTrustedIssuer);
	});

	it("reports when there is no identifier to resolve at all", async () => {
		// Unreachable through the verifiers now that the schema runs first --
		// a valid credential always yields an issuer identifier -- so the
		// guard is exercised directly.
		const result = await resolveVcdm2IssuerPublicKey(
			{ context: makeContext(), pkResolverEngine: makeResolver(null) },
			{ alg: "ES256" },
			{},
		);

		expect(result.success).toBe(false);
		if (!result.success) expect(result.error).toBe(CredentialVerificationError.CannotResolveIssuerPublicKey);
	});
});
