/**
 * The two DIIP v5 "Validity and Revocation Algorithm" checks, shared by the credential verifiers.
 *
 * - validity window: `validFrom` / `validUntil` (or their `nbf` / `exp` equivalents)
 * - revocation: IETF Token Status List
 */

import { CredentialVerificationError } from "../error";
import { Context, HttpClient, PublicKeyResolverEngineI } from "../interfaces";
import { ValidityClaims, checkValidityWindow, extractValidityInfo } from "../utils/credentialValidity";
import {
	StatusListCache,
	TokenStatus,
	createStatusListCache,
	extractStatusListReference,
	resolveTokenStatus,
} from "../utils/tokenStatusList";

export type ValidityAndStatusChecker = (claims: Record<string, unknown>) => Promise<CredentialVerificationError | null>;

/**
 * The issuer identifier of a credential.
 *
 * SD-JWT VC and JWT VC JSON use the JOSE `iss` claim. A W3C VCDM 2.0 credential secured with
 * SD-JWT (VC-JOSE-COSE §3.2.1) instead carries the VCDM `issuer` property, which is either an
 * identifier string or an object with an `id`.
 */
export function resolveIssuerIdentifier(claims: Record<string, unknown>): string | null {
	if (typeof claims.iss === "string") {
		return claims.iss;
	}
	const issuer = claims.issuer;
	if (typeof issuer === "string") {
		return issuer;
	}
	if (typeof issuer === "object" && issuer !== null && typeof (issuer as { id?: unknown }).id === "string") {
		return (issuer as { id: string }).id;
	}
	return null;
}

/**
 * Build a checker bound to one verifier's context. The returned function reports the first
 * problem it finds, or `null` when the credential is valid and not revoked.
 *
 * A status list that cannot be reached (offline wallet, issuer downtime) is logged as a warning
 * rather than reported as an error — refusing to show a credential because its status endpoint is
 * unavailable would make the wallet unusable offline.
 */
export function createValidityAndStatusChecker(args: {
	context: Context;
	httpClient: HttpClient;
	pkResolverEngine: PublicKeyResolverEngineI;
}): ValidityAndStatusChecker {
	const statusListCache: StatusListCache = createStatusListCache();

	return async (claims: Record<string, unknown>): Promise<CredentialVerificationError | null> => {
		const validityError = checkValidityWindow(
			extractValidityInfo(claims as ValidityClaims),
			args.context.clockTolerance,
		);
		if (validityError) {
			return validityError;
		}

		const reference = extractStatusListReference(claims);
		if (!reference) {
			return null;
		}

		const resolution = await resolveTokenStatus({
			reference,
			httpClient: args.httpClient,
			expectedIssuer: resolveIssuerIdentifier(claims) ?? undefined,
			clockTolerance: args.context.clockTolerance,
			cache: statusListCache,
			resolveKey: async ({ identifier, kid }) => {
				const result = await args.pkResolverEngine.resolve({ identifier, kid });
				return result.success ? result.value.jwk : null;
			},
		});

		if (!resolution.ok) {
			console.warn(`Could not determine the revocation status of the credential: ${resolution.reason}`);
			return null;
		}

		if (resolution.status === TokenStatus.INVALID) {
			return CredentialVerificationError.RevokedCredential;
		}
		if (resolution.status === TokenStatus.SUSPENDED) {
			return CredentialVerificationError.SuspendedCredential;
		}
		return null;
	};
}
