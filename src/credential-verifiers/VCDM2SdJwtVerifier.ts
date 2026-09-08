import { Context, CredentialVerifier, PublicKeyResolverEngineI, HttpClient } from "../interfaces";
import { CredentialVerificationError } from "../error";
import { CustomResult } from "../types";
import { importJWK, importX509, JWK, jwtVerify, KeyLike } from "jose";
import { verifyCertificate } from "../utils/verifyCertificate";
import { decodeVcdm2SdJwt, issuerIdentifier } from "../utils/vcdm2";

/**
 * Verifier for a W3C VCDM 2.0 credential carried inside an SD-JWT (DIIP v5).
 *
 * Only the issuer-signed JWT — everything before the first `~` — is covered
 * by the issuer's signature, so that is what gets verified. Disclosures are
 * integrity-protected by the digests inside that payload, and expanding them
 * is the parser's job.
 *
 * Registered ahead of SDJWTVCVerifier: that verifier resolves the issuer key
 * from an `iss` claim, which a VCDM 2.0 credential need not carry — its
 * issuer lives in the credential's own `issuer` member.
 */
export function VCDM2SdJwtVerifier(args: { context: Context, pkResolverEngine: PublicKeyResolverEngineI, httpClient: HttpClient }): CredentialVerifier {
	let errors: { error: CredentialVerificationError, message: string }[] = [];
	const logError = (error: CredentialVerificationError, message: string): void => {
		errors.push({ error, message });
	};

	const resolveIssuerPublicKey = async (
		header: any,
		payload: any,
	): Promise<CustomResult<Uint8Array | KeyLike, CredentialVerificationError>> => {
		const alg = typeof header?.alg === "string" ? header.alg : undefined;
		if (!alg) {
			logError(CredentialVerificationError.InvalidFormat, "JWS header has no alg");
			return { success: false, error: CredentialVerificationError.InvalidFormat };
		}

		const x5c = header.x5c as string[] | undefined;
		if (Array.isArray(x5c) && x5c.length > 0) {
			const delegateTrustToBackend = args.context.delegateTrustToBackend ?? true;
			const trustedCertificates = args.context.trustedCertificates ?? [];

			if (!delegateTrustToBackend && trustedCertificates.length > 0) {
				const lastCertificate: string = x5c[x5c.length - 1];
				const lastCertificatePem = `-----BEGIN CERTIFICATE-----\n${lastCertificate}\n-----END CERTIFICATE-----`;

				// A malformed certificate makes the parser throw rather than
				// return false; letting that escape would abort the whole
				// verifying engine, which does not catch.
				let certificateValidationResult: unknown = false;
				try {
					certificateValidationResult = await verifyCertificate(lastCertificatePem, trustedCertificates);
				} catch (err) {
					logError(CredentialVerificationError.NotTrustedIssuer, `Could not validate issuer certificate chain: ${err}`);
					return { success: false, error: CredentialVerificationError.NotTrustedIssuer };
				}

				const lastCertificateIsRootCa = trustedCertificates.map((c) => c.trim()).includes(lastCertificatePem);
				if (!(certificateValidationResult === true || lastCertificateIsRootCa)) {
					logError(CredentialVerificationError.NotTrustedIssuer, "Issuer is not trusted");
					return { success: false, error: CredentialVerificationError.NotTrustedIssuer };
				}
			}

			try {
				const issuerPemCert = `-----BEGIN CERTIFICATE-----\n${x5c[0]}\n-----END CERTIFICATE-----`;
				return { success: true, value: await importX509(issuerPemCert, alg) };
			} catch (err) {
				logError(CredentialVerificationError.CannotImportIssuerPublicKey, `Cannot import issuer public key from x5c: ${err}`);
				return { success: false, error: CredentialVerificationError.CannotImportIssuerPublicKey };
			}
		}

		// Prefer the JWS `kid`, then the JWT's own `iss`, and finally the
		// credential's `issuer` member — a VCDM 2.0 credential need not
		// duplicate its issuer into a registered JWT claim.
		const identifier = typeof header.kid === "string"
			? header.kid
			: typeof payload?.iss === "string"
				? payload.iss
				: issuerIdentifier(payload?.issuer);

		if (!identifier) {
			logError(CredentialVerificationError.CannotResolveIssuerPublicKey, "No kid, iss or issuer to resolve");
			return { success: false, error: CredentialVerificationError.CannotResolveIssuerPublicKey };
		}

		const resolution = await args.pkResolverEngine.resolve({ identifier });
		if (!resolution.success) {
			logError(CredentialVerificationError.CannotResolveIssuerPublicKey, `Could not resolve ${identifier}`);
			return { success: false, error: CredentialVerificationError.CannotResolveIssuerPublicKey };
		}

		try {
			return { success: true, value: await importJWK(resolution.value.jwk, alg) };
		} catch (err: unknown) {
			/* v8 ignore next -- importJWK only ever throws Errors */
			const message = err instanceof Error ? err.message : String(err);
			logError(CredentialVerificationError.CannotImportIssuerPublicKey, `Cannot import resolved issuer public key: ${message}`);
			return { success: false, error: CredentialVerificationError.CannotImportIssuerPublicKey };
		}
	};

	return {
		async verify({ rawCredential }) {
			errors = [];

			const decoded = decodeVcdm2SdJwt(rawCredential);
			if (!decoded) {
				return { success: false, error: CredentialVerificationError.VerificationProcessNotStarted };
			}

			const issuerPublicKey = await resolveIssuerPublicKey(decoded.header, decoded.payload);
			if (!issuerPublicKey.success) {
				return { success: false, error: issuerPublicKey.error };
			}

			try {
				await jwtVerify(decoded.issuerJwt, issuerPublicKey.value, {
					clockTolerance: args.context.clockTolerance,
				});
			} catch (err: unknown) {
				if (err instanceof Error && err.name === "JWTExpired") {
					logError(CredentialVerificationError.ExpiredCredential, `Credential is expired: ${err}`);
					return { success: false, error: CredentialVerificationError.ExpiredCredential };
				}
				logError(CredentialVerificationError.InvalidSignature, `Issuer signature verification failed: ${err}`);
				return { success: false, error: CredentialVerificationError.InvalidSignature };
			}

			let holderJwk: JWK = {} as JWK;
			const cnf = decoded.payload?.cnf as { jwk?: JWK } | undefined;
			if (cnf?.jwk) holderJwk = cnf.jwk;

			return { success: true, value: { holderPublicKey: holderJwk } };
		},
	};
}
