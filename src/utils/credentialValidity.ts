/**
 * Credential validity window checks.
 *
 * DIIP v5: "DIIP-compliant implementations MUST support checking the validity status of a
 * Digital Credential using `validFrom` and `validUntil` when they are specified."
 *
 * The JWT-native equivalents (`nbf` / `exp`) map onto the same window, so both credential
 * families share one check.
 */

import { CredentialVerificationError } from "../error";

export type ValidityInfo = {
	validFrom?: Date;
	validUntil?: Date;
	signed?: Date;
};

/**
 * Claims that can carry a validity window: the JWT registered claims and the
 * W3C VCDM 2.0 properties.
 */
export type ValidityClaims = {
	exp?: number;
	iat?: number;
	nbf?: number;
	validFrom?: string;
	validUntil?: string;
};

function parseDateClaim(value: string | undefined): Date | undefined {
	if (!value) {
		return undefined;
	}
	const date = new Date(value);
	return Number.isNaN(date.getTime()) ? undefined : date;
}

/**
 * Derive the validity window from a credential's claims.
 *
 * The VCDM 2.0 XMLSchema dateTime properties take precedence over the numeric JWT claims when
 * both are present, since a VCDM credential's own `validFrom`/`validUntil` are authoritative.
 */
export function extractValidityInfo(claims: ValidityClaims): ValidityInfo {
	const info: ValidityInfo = {};

	const validUntil = parseDateClaim(claims.validUntil);
	if (validUntil) {
		info.validUntil = validUntil;
	}
	else if (claims.exp) {
		info.validUntil = new Date(claims.exp * 1000);
	}

	const validFrom = parseDateClaim(claims.validFrom);
	if (validFrom) {
		info.validFrom = validFrom;
	}
	else if (claims.nbf) {
		info.validFrom = new Date(claims.nbf * 1000);
	}

	if (claims.iat) {
		info.signed = new Date(claims.iat * 1000);
	}

	return info;
}

/**
 * Check a credential's validity window against the current time.
 *
 * @param clockTolerance leeway in seconds, matching the tolerance used for signature verification.
 * @returns the verification error to report, or `null` when the credential is inside its window.
 *   Absent bounds mean "valid indefinitely" per the VCDM.
 */
export function checkValidityWindow(
	validityInfo: ValidityInfo,
	clockTolerance: number = 0,
	now: Date = new Date(),
): CredentialVerificationError | null {
	const toleranceMs = clockTolerance * 1000;

	if (validityInfo.validUntil && validityInfo.validUntil.getTime() + toleranceMs < now.getTime()) {
		return CredentialVerificationError.ExpiredCredential;
	}
	if (validityInfo.validFrom && validityInfo.validFrom.getTime() - toleranceMs > now.getTime()) {
		return CredentialVerificationError.NotYetValidCredential;
	}
	return null;
}
