import { SDJwt } from "@sd-jwt/core";
import type { HasherAndAlg } from "@sd-jwt/types";
import { Context, CredentialVerifier, PublicKeyResolverEngineI, HttpClient } from "../interfaces";
import { CredentialVerificationError } from "../error";
import { CustomResult } from "../types";
import { importJWK, importX509, JWK, jwtVerify, KeyLike } from "jose";
import { fromBase64Url, toBase64Url } from "../utils/util";
import { verifyCertificate } from "../utils/verifyCertificate";
import { createDidResolver, findPublicKeyInDidDocument } from "../resolvers/didResolver";
import { createValidityAndStatusChecker, resolveIssuerIdentifier } from "./checkValidityAndStatus";

type ParsedSdJwtVcWithPrettyClaims = Record<string, unknown> & {
	cnf?: {
		jwk?: JWK;
		/** DIIP v5 binds the holder by a `kid` pointing into their DID document's `authentication`. */
		kid?: string;
	};
};

export function SDJWTVCVerifier(args: { context: Context, pkResolverEngine: PublicKeyResolverEngineI, httpClient: HttpClient }): CredentialVerifier {
	let errors: { error: CredentialVerificationError, message: string }[] = [];
	const logError = (error: CredentialVerificationError, message: string): void => {
		errors.push({ error, message });
	}

	const encoder = new TextEncoder();
	const decoder = new TextDecoder();

	const resolveDid = createDidResolver({ httpClient: args.httpClient });
	const checkValidityAndStatus = createValidityAndStatusChecker(args);

	/**
	 * Resolve the holder's public key from a `cnf` claim. DIIP v5 binds the holder via a
	 * `cnf.kid` DID URL into the holder's `authentication` relationship; the wwWallet-native
	 * `cnf.jwk` form stays supported so already-issued credentials keep verifying.
	 */
	const resolveHolderJwkFromCnf = async (cnf: ParsedSdJwtVcWithPrettyClaims["cnf"]): Promise<JWK | null> => {
		if (cnf?.jwk) {
			return cnf.jwk;
		}
		if (!cnf?.kid || !cnf.kid.startsWith("did:")) {
			return null;
		}
		const did = cnf.kid.split("#")[0];
		const resolution = await resolveDid(did);
		if (!resolution.resolved || !resolution.didDocument) {
			return null;
		}
		return findPublicKeyInDidDocument(resolution.didDocument, cnf.kid, "authentication");
	};

	// Encoding the string into a Uint8Array
	const hasherAndAlgorithm: HasherAndAlg = {
		hasher: (data: string | ArrayBuffer, alg: string) => {
			const encoded =
				typeof data === 'string' ? encoder.encode(data) : new Uint8Array(data);

			return args.context.subtle.digest(alg, encoded).then((v) => new Uint8Array(v));
		},
		alg: 'sha-256',
	};

	const parse = async (rawCredential: string) => {
		try {
			const credential = await SDJwt.fromEncode(rawCredential, hasherAndAlgorithm.hasher);
			const parsedSdJwtWithPrettyClaims = await (await SDJwt.fromEncode(rawCredential, hasherAndAlgorithm.hasher)).getClaims<ParsedSdJwtVcWithPrettyClaims>(hasherAndAlgorithm.hasher);
			return { credential, parsedSdJwtWithPrettyClaims };
		}
		catch (err) {
			if (err instanceof Error) {
				logError(CredentialVerificationError.InvalidFormat, "Invalid format. Error: " + err.name + ": " + err.message);
			}
			return CredentialVerificationError.InvalidFormat;
		}

	}

	const getHolderPublicKey = async (rawCredential: string): Promise<CustomResult<Uint8Array | KeyLike, CredentialVerificationError>> => {
		const parseResult = await parse(rawCredential);
		if (parseResult === CredentialVerificationError.InvalidFormat) {
			return {
				success: false,
				error: CredentialVerificationError.InvalidFormat,
			}
		}
		const cnf = parseResult.parsedSdJwtWithPrettyClaims.cnf;
		const holderJwk = await resolveHolderJwkFromCnf(cnf);

		if (holderJwk && parseResult.credential.jwt && parseResult.credential.jwt.header && typeof parseResult.credential.jwt.header["alg"] === 'string') {
			try {
				const holderPublicKey = await importJWK(holderJwk, parseResult.credential.jwt.header["alg"]);
				return {
					success: true,
					value: holderPublicKey,
				}
			}
			catch (err: any) {
				logError(CredentialVerificationError.CannotImportHolderPublicKey, `Error on getHolderPublicKey(): Could not import holder's public key. Cause: ${err.message}`);
				return {
					success: false,
					error: CredentialVerificationError.CannotImportHolderPublicKey,
				}
			}

		}
		return {
			success: false,
			error: CredentialVerificationError.CannotExtractHolderPublicKey
		}

	}

	const verifyIssuerSignature = async (rawCredential: string): Promise<CustomResult<{}, CredentialVerificationError>> => {
		const parsedSdJwt = await (async () => {
			try {
				return (await SDJwt.fromEncode(rawCredential, hasherAndAlgorithm.hasher)).jwt;
			}
			catch (err) {
				if (err instanceof Error) {
					logError(CredentialVerificationError.InvalidFormat, "Invalid format. Error: " + err.name + ": " + err.message);
				}
				return CredentialVerificationError.InvalidFormat;
			}
		})();

		if (parsedSdJwt === CredentialVerificationError.InvalidFormat) {
			logError(CredentialVerificationError.InvalidFormat, "Invalid format");
			return {
				success: false,
				error: CredentialVerificationError.InvalidFormat
			}
		}

		const getIssuerPublicKey = async (): Promise<CustomResult<Uint8Array | KeyLike, CredentialVerificationError>> => {
			const x5c = (parsedSdJwt?.header?.x5c as string[]) ?? "";
			const alg = (parsedSdJwt?.header?.alg as string) ?? "";
			if (x5c && x5c instanceof Array && x5c.length > 0 && typeof alg === 'string') { // extract public key from certificate
				// Only validate certificate chain if not delegating to backend
				// Trust evaluation is now delegated to AuthZEN at the protocol level
				const delegateTrustToBackend = args.context.delegateTrustToBackend ?? true;
				const trustedCertificates = args.context.trustedCertificates ?? [];

				if (!delegateTrustToBackend && trustedCertificates.length > 0) {
					const lastCertificate: string = x5c[x5c.length - 1];
					const lastCertificatePem = `-----BEGIN CERTIFICATE-----\n${lastCertificate}\n-----END CERTIFICATE-----`;
					const certificateValidationResult = await verifyCertificate(lastCertificatePem, trustedCertificates);
					const lastCertificateIsRootCa = trustedCertificates.map((c) => c.trim()).includes(lastCertificatePem);
					const rootCertIsTrusted = certificateValidationResult === true || lastCertificateIsRootCa;
					if (!rootCertIsTrusted) {
						logError(CredentialVerificationError.NotTrustedIssuer, "Error on getIssuerPublicKey(): Issuer is not trusted");
						return {
							success: false,
							error: CredentialVerificationError.NotTrustedIssuer,
						};
					}
				}

				try {
					const issuerPemCert = `-----BEGIN CERTIFICATE-----\n${x5c[0]}\n-----END CERTIFICATE-----`;
					const issuerPublicKey = await importX509(issuerPemCert, alg);
					return {
						success: true,
						value: issuerPublicKey,
					};
				}
				catch (err) {
					logError(CredentialVerificationError.CannotImportIssuerPublicKey, `Error on getIssuerPublicKey(): Importing key failed because: ${err}`);
					return {
						success: false,
						error: CredentialVerificationError.CannotImportIssuerPublicKey,
					}
				}
			}
			// SD-JWT VC identifies the issuer by `iss`; a W3C VCDM 2.0 credential secured with
			// SD-JWT uses the VCDM `issuer` property instead, which may be a string or an object.
			const issuerIdentifier = parsedSdJwt?.payload ? resolveIssuerIdentifier(parsedSdJwt.payload) : null;

			if (issuerIdentifier && typeof alg === 'string') {
				// The `kid` narrows which verification method of a DID document signed the credential.
				const kid = typeof parsedSdJwt?.header?.kid === 'string' ? parsedSdJwt.header.kid : undefined;
				const publicKeyResolutionResult = await args.pkResolverEngine.resolve({ identifier: issuerIdentifier, kid });
				if (!publicKeyResolutionResult.success) {
					logError(CredentialVerificationError.CannotResolveIssuerPublicKey, "CannotResolveIssuerPublicKey");
					return {
						success: false,
						error: CredentialVerificationError.CannotResolveIssuerPublicKey,
					}
				}
				try {
					const publicKey = await importJWK(publicKeyResolutionResult.value.jwk, alg);
					return {
						success: true,
						value: publicKey,
					}
				}
				catch (err: any) {
					logError(CredentialVerificationError.CannotImportIssuerPublicKey, `Error on getIssuerPublicKey(): Cannot import issuer's public key after resolved from the resolver. Cause ${err.message}`)
					return {
						success: false,
						error: CredentialVerificationError.CannotImportIssuerPublicKey,
					}
				}
			}
			logError(CredentialVerificationError.CannotResolveIssuerPublicKey, "CannotResolveIssuerPublicKey");
			return {
				success: false,
				error: CredentialVerificationError.CannotResolveIssuerPublicKey,
			}
		};

		const issuerPublicKeyResult = await getIssuerPublicKey();

		if (!issuerPublicKeyResult.success) {
			logError(CredentialVerificationError.CannotResolveIssuerPublicKey, "CannotResolveIssuerPublicKey");
			return {
				success: false,
				error: issuerPublicKeyResult.error,
			}
		}
		const publicKey = issuerPublicKeyResult.value;

		try {
			await jwtVerify(rawCredential.split('~')[0], publicKey, { clockTolerance: args.context.clockTolerance });
		}
		catch (err: unknown) {
			if (err instanceof Error && err.name == "JWTExpired") {
				logError(CredentialVerificationError.ExpiredCredential, `Error on verifyIssuerSignature(): Credential is expired. Cause: ${err}`);
				return {
					success: false,
					error: CredentialVerificationError.ExpiredCredential,
				}
			}

			logError(CredentialVerificationError.InvalidSignature, `Error on verifyIssuerSignature(): Issuer signature verification failed. Cause: ${err}`);
			return {
				success: false,
				error: CredentialVerificationError.InvalidSignature,
			}
		}

		return {
			success: true,
			value: {},
		}
	}

	const verifyKbJwt = async (rawPresentation: string, opts: {
		expectedNonce?: string;
		expectedAudience?: string;
	}): Promise<CustomResult<{}, CredentialVerificationError>> => {
		const kbJwt = rawPresentation.split('~')[rawPresentation.split('~').length - 1];
		let temp = rawPresentation.split('~');
		temp = temp.slice(0, temp.length - 1);
		const rawCredentialWithoutKbJwt = temp.join('~') + '~';

		const publicKeyResult = await getHolderPublicKey(rawCredentialWithoutKbJwt);
		if (!publicKeyResult.success) {
			logError(CredentialVerificationError.CannotExtractHolderPublicKey, "CannotExtractHolderPublicKey");
			return {
				success: false,
				error: publicKeyResult.error,
			}
		}
		const holderPublicKey = publicKeyResult.value;
		const kbJwtDecodedPayload: Record<string, unknown> = JSON.parse(decoder.decode(fromBase64Url(kbJwt.split('.')[1])));
		if (!kbJwtDecodedPayload.sd_hash || !kbJwtDecodedPayload.nonce || !kbJwtDecodedPayload.aud) {
			logError(CredentialVerificationError.KbJwtVerificationFailedMissingParameters, "Error on verifyKbJwt(): Once of sd_hash, nonce and aud are missing from the kbjwt payload");
			return {
				success: false,
				error: CredentialVerificationError.KbJwtVerificationFailedMissingParameters,
			}
		}
		const { sd_hash, nonce, aud } = kbJwtDecodedPayload as { sd_hash: string, nonce: string, aud: string };

		const data = encoder.encode(rawCredentialWithoutKbJwt);

		const hashBuffer = await args.context.subtle.digest('SHA-256', data);
		const calculatedSdHash = toBase64Url(hashBuffer);
		if (calculatedSdHash !== sd_hash) {
			logError(CredentialVerificationError.KbJwtVerificationFailedWrongSdHash, "Error on verifyKbJwt(): Invalid sd_hash");
			return {
				success: false,
				error: CredentialVerificationError.KbJwtVerificationFailedWrongSdHash,
			}
		}

		if (opts.expectedAudience && opts.expectedAudience !== aud) {
			logError(CredentialVerificationError.KbJwtVerificationFailedUnexpectedAudience, "Error on verifyKbJwt(): Invalid aud");
			return {
				success: false,
				error: CredentialVerificationError.KbJwtVerificationFailedUnexpectedAudience,
			}
		}

		if (opts.expectedNonce && opts.expectedNonce !== nonce) {
			logError(CredentialVerificationError.KbJwtVerificationFailedUnexpectedNonce, "Error on verifyKbJwt(): Invalid nonce");
			return {
				success: false,
				error: CredentialVerificationError.KbJwtVerificationFailedUnexpectedNonce,
			}
		}

		try {
			await jwtVerify(kbJwt, holderPublicKey, { clockTolerance: args.context.clockTolerance });
		}
		catch (err: any) {
			logError(CredentialVerificationError.KbJwtVerificationFailedSignatureValidation, "Error on verifyKbJwt(): Invalid KB-JWT signature");
			return {
				success: false,
				error: CredentialVerificationError.KbJwtVerificationFailedSignatureValidation,
			};
		}
		return {
			success: true,
			value: {},
		}
	}

	return {
		async verify({ rawCredential, opts }) {
			errors = []; // re-initialize error array
			if (typeof rawCredential !== 'string') {
				return {
					success: false,
					error: CredentialVerificationError.InvalidDatatype,
				};
			}

			// Issuer Signature validation
			const issuerSignatureVerificationResult = await verifyIssuerSignature(rawCredential);
			if (!issuerSignatureVerificationResult.success) {
				return {
					success: false,
					error: errors.length > 0 ? errors[0].error : CredentialVerificationError.UnknownProblem,
				}
			}

			// KB-JWT validation
			if (!rawCredential.endsWith('~')) { // contains kbjwt
				const verifyKbJwtResult = await verifyKbJwt(rawCredential, opts);
				if (!verifyKbJwtResult.success) {
					return {
						success: false,
						error: errors.length > 0 ? errors[0].error : CredentialVerificationError.UnknownProblem,
					}
				}
			}

			// Extract holder public key JWK directly from cnf claim to avoid
			// importing and re-exporting through Web Crypto (jose importJWK
			// creates non-extractable CryptoKeys in browsers by default).
			const parseResult = await parse(rawCredential);

			// DIIP v5 validity and revocation algorithm. `jwtVerify` above already rejects a
			// stale `exp`, but not a VCDM-style `validUntil`, a `validFrom` in the future, or a
			// revoked entry in the issuer's Token Status List.
			if (parseResult !== CredentialVerificationError.InvalidFormat) {
				const statusError = await checkValidityAndStatus(parseResult.parsedSdJwtWithPrettyClaims);
				if (statusError) {
					logError(statusError, `Credential validity/status check failed: ${statusError}`);
					return { success: false, error: statusError };
				}
			}

			const holderPublicKey = parseResult === CredentialVerificationError.InvalidFormat
				? null
				: await resolveHolderJwkFromCnf(parseResult.parsedSdJwtWithPrettyClaims.cnf);
			if (!holderPublicKey) {
				logError(CredentialVerificationError.CannotExtractHolderPublicKey, "Could not extract holder public key");
				return {
					success: false,
					error: errors.length > 0 ? errors[0].error : CredentialVerificationError.UnknownProblem,
				}
			}

			return {
				success: true,
				value: {
					valid: true,
					holderPublicKey,
				},
			}
		},
	}
}
