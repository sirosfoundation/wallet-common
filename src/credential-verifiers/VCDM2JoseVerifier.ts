import { Context, CredentialVerifier, PublicKeyResolverEngineI, HttpClient } from "../interfaces";
import { CredentialVerificationError } from "../error";
import { CustomResult } from "../types";
import { importJWK, importX509, JWK, jwtVerify, KeyLike } from "jose";
import { verifyCertificate } from "../utils/verifyCertificate";
import { decodeEnvelopedVcdm2, issuerIdentifier } from "../utils/vcdm2";

/**
 * Verifier for W3C VCDM 2.0 credentials secured with an enveloping JOSE proof.
 *
 * Structurally the same job as JWTVCJSONVerifier — check the issuer's JWS —
 * but the issuer identifier lives in the credential's `issuer` member rather
 * than an `iss` claim, so key resolution differs. Registering this ahead of
 * JWTVCJSONVerifier matters: that verifier claims *any* non-SD-JWT compact
 * JWS, so it would otherwise swallow these and resolve the wrong key.
 */
export function VCDM2JoseVerifier(args: { context: Context, pkResolverEngine: PublicKeyResolverEngineI, httpClient: HttpClient }): CredentialVerifier {
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

		// An x5c chain, when present, is the most direct route to the key.
		const x5c = header.x5c as string[] | undefined;
		if (Array.isArray(x5c) && x5c.length > 0) {
			const delegateTrustToBackend = args.context.delegateTrustToBackend ?? true;
			const trustedCertificates = args.context.trustedCertificates ?? [];

			if (!delegateTrustToBackend && trustedCertificates.length > 0) {
				const lastCertificate: string = x5c[x5c.length - 1];
				const lastCertificatePem = `-----BEGIN CERTIFICATE-----\n${lastCertificate}\n-----END CERTIFICATE-----`;

				// A malformed certificate makes the parser throw rather than
				// return false. Treat that as untrusted: letting it escape
				// would abort the whole verifying engine, which does not catch.
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

		// Otherwise resolve by identifier. Prefer the JWS `kid` (which for
		// VC-JOSE-COSE names a verification method) and fall back to the
		// credential's own issuer.
		const identifier = typeof header.kid === "string"
			? header.kid
			: issuerIdentifier(payload?.issuer);

		if (!identifier) {
			logError(CredentialVerificationError.CannotResolveIssuerPublicKey, "No kid or issuer to resolve");
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

			const decoded = decodeEnvelopedVcdm2(rawCredential);
			if (!decoded) {
				return { success: false, error: CredentialVerificationError.VerificationProcessNotStarted };
			}

			const issuerPublicKey = await resolveIssuerPublicKey(decoded.header, decoded.payload);
			if (!issuerPublicKey.success) {
				return { success: false, error: issuerPublicKey.error };
			}

			try {
				await jwtVerify(rawCredential as string, issuerPublicKey.value, {
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

			// Holder binding is optional for an enveloped VCDM 2.0 credential;
			// surface `cnf.jwk` when the issuer bound one, as SD-JWT VC does.
			let holderJwk: JWK = {} as JWK;
			const cnf = decoded.payload?.cnf as { jwk?: JWK } | undefined;
			if (cnf?.jwk) holderJwk = cnf.jwk;

			return { success: true, value: { holderPublicKey: holderJwk } };
		},
	};
}
