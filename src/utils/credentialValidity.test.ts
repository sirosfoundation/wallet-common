import { describe, expect, it } from "vitest";
import { checkValidityWindow, extractValidityInfo } from "./credentialValidity";
import { CredentialVerificationError } from "../error";

const NOW = new Date("2026-06-01T12:00:00Z");
const seconds = (date: string) => Math.floor(new Date(date).getTime() / 1000);

describe("extractValidityInfo", () => {
	it("maps the JWT registered claims", () => {
		const info = extractValidityInfo({
			nbf: seconds("2026-01-01T00:00:00Z"),
			exp: seconds("2027-01-01T00:00:00Z"),
			iat: seconds("2026-01-01T00:00:00Z"),
		});

		expect(info.validFrom?.toISOString()).toBe("2026-01-01T00:00:00.000Z");
		expect(info.validUntil?.toISOString()).toBe("2027-01-01T00:00:00.000Z");
		expect(info.signed?.toISOString()).toBe("2026-01-01T00:00:00.000Z");
	});

	it("maps the VCDM 2.0 validFrom / validUntil properties", () => {
		const info = extractValidityInfo({
			validFrom: "2026-01-01T00:00:00Z",
			validUntil: "2027-01-01T00:00:00Z",
		});

		expect(info.validFrom?.toISOString()).toBe("2026-01-01T00:00:00.000Z");
		expect(info.validUntil?.toISOString()).toBe("2027-01-01T00:00:00.000Z");
	});

	it("prefers the VCDM properties when both forms are present", () => {
		const info = extractValidityInfo({
			validUntil: "2027-01-01T00:00:00Z",
			exp: seconds("2026-02-01T00:00:00Z"),
		});

		expect(info.validUntil?.toISOString()).toBe("2027-01-01T00:00:00.000Z");
	});

	it("ignores unparseable date strings", () => {
		expect(extractValidityInfo({ validFrom: "not-a-date" }).validFrom).toBeUndefined();
	});

	it("returns an empty window when nothing is specified", () => {
		expect(extractValidityInfo({})).toEqual({});
	});
});

describe("checkValidityWindow", () => {
	it("accepts a credential inside its window", () => {
		expect(checkValidityWindow(
			{ validFrom: new Date("2026-01-01T00:00:00Z"), validUntil: new Date("2027-01-01T00:00:00Z") },
			0,
			NOW,
		)).toBeNull();
	});

	it("treats an absent window as valid indefinitely", () => {
		expect(checkValidityWindow({}, 0, NOW)).toBeNull();
	});

	it("reports an expired credential", () => {
		expect(checkValidityWindow({ validUntil: new Date("2026-05-01T00:00:00Z") }, 0, NOW))
			.toBe(CredentialVerificationError.ExpiredCredential);
	});

	it("reports a credential that is not yet valid", () => {
		expect(checkValidityWindow({ validFrom: new Date("2026-07-01T00:00:00Z") }, 0, NOW))
			.toBe(CredentialVerificationError.NotYetValidCredential);
	});

	it("applies the clock tolerance at the validUntil boundary", () => {
		const justExpired = { validUntil: new Date(NOW.getTime() - 30_000) };

		expect(checkValidityWindow(justExpired, 60, NOW)).toBeNull();
		expect(checkValidityWindow(justExpired, 10, NOW)).toBe(CredentialVerificationError.ExpiredCredential);
	});

	it("applies the clock tolerance at the validFrom boundary", () => {
		const justStarted = { validFrom: new Date(NOW.getTime() + 30_000) };

		expect(checkValidityWindow(justStarted, 60, NOW)).toBeNull();
		expect(checkValidityWindow(justStarted, 10, NOW)).toBe(CredentialVerificationError.NotYetValidCredential);
	});

	it("reports expiry ahead of a future validFrom when both are violated", () => {
		expect(checkValidityWindow(
			{ validFrom: new Date("2026-07-01T00:00:00Z"), validUntil: new Date("2026-05-01T00:00:00Z") },
			0,
			NOW,
		)).toBe(CredentialVerificationError.ExpiredCredential);
	});
});
