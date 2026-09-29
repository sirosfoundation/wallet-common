import { importJWK, importX509, KeyLike } from "jose";
import { Context, PublicKeyResolverEngineI } from "../interfaces";
import { CredentialVerificationError } from "../error";
import { CustomResult } from "../types";
import { verifyCertificate } from "../utils/verifyCertificate";
import { issuerIdentifier } from "../utils/vcdm2";

/**
 * Resolve the issuer's public key for a VCDM 2.0 credential secured with a
 * JWS, whether enveloping (`vc+jwt`) or carried in an SD-JWT.
 *
 * Shared by VCDM2JoseVerifier and VCDM2SdJwtVerifier, which differ only in
 * whether a JWT `iss` claim participates in identifier resolution.
 */
export async function resolveVcdm2IssuerPublicKey(
	args: { context: Context; pkResolverEngine: PublicKeyResolverEngineI },
	header: any,
	payload: any,
	options: { useIssClaim?: boolean } = {},
): Promise<CustomResult<Uint8Array | KeyLike, CredentialVerificationError>> {
	const alg = typeof header?.alg === "string" ? header.alg : undefined;
	if (!alg) {
		return { success: false, error: CredentialVerificationError.InvalidFormat };
	}

	// An x5c chain, when present, is the most direct route to the key.
	const x5c = header.x5c as string[] | undefined;
	if (Array.isArray(x5c) && x5c.length > 0) {
		const delegateTrustToBackend = args.context.delegateTrustToBackend ?? true;
		const trustedCertificates = args.context.trustedCertificates ?? [];

		if (!delegateTrustToBackend) {
			// Evaluating trust locally with no trust anchors configured cannot
			// establish anything. Skipping the check in that case would accept
			// any issuer that presents a chain, so it fails instead.
			if (trustedCertificates.length === 0) {
				return { success: false, error: CredentialVerificationError.NotTrustedIssuer };
			}

			const lastCertificate: string = x5c[x5c.length - 1];
			const lastCertificatePem = `-----BEGIN CERTIFICATE-----\n${lastCertificate}\n-----END CERTIFICATE-----`;

			// A malformed certificate makes the parser throw rather than return
			// false. Treat that as untrusted: letting it escape would abort the
			// whole verifying engine, which does not catch.
			let certificateValidationResult: unknown = false;
			try {
				certificateValidationResult = await verifyCertificate(lastCertificatePem, trustedCertificates);
			} catch {
				return { success: false, error: CredentialVerificationError.NotTrustedIssuer };
			}

			const lastCertificateIsRootCa = trustedCertificates.map((c) => c.trim()).includes(lastCertificatePem);
			if (!(certificateValidationResult === true || lastCertificateIsRootCa)) {
				return { success: false, error: CredentialVerificationError.NotTrustedIssuer };
			}
		}

		try {
			const issuerPemCert = `-----BEGIN CERTIFICATE-----\n${x5c[0]}\n-----END CERTIFICATE-----`;
			return { success: true, value: await importX509(issuerPemCert, alg) };
		} catch {
			return { success: false, error: CredentialVerificationError.CannotImportIssuerPublicKey };
		}
	}

	// Otherwise resolve by identifier. The JWS `kid` names a verification
	// method and wins; a VCDM 2.0 credential need not duplicate its issuer
	// into a registered JWT claim, so the credential's own `issuer` is the
	// last resort.
	const identifier = typeof header.kid === "string"
		? header.kid
		: options.useIssClaim && typeof payload?.iss === "string"
			? payload.iss
			: issuerIdentifier(payload?.issuer);

	if (!identifier) {
		return { success: false, error: CredentialVerificationError.CannotResolveIssuerPublicKey };
	}

	const resolution = await args.pkResolverEngine.resolve({ identifier });
	if (!resolution.success) {
		return { success: false, error: CredentialVerificationError.CannotResolveIssuerPublicKey };
	}

	try {
		return { success: true, value: await importJWK(resolution.value.jwk, alg) };
	} catch {
		return { success: false, error: CredentialVerificationError.CannotImportIssuerPublicKey };
	}
}
