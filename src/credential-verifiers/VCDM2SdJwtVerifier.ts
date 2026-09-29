import { Context, CredentialVerifier, PublicKeyResolverEngineI, HttpClient } from "../interfaces";
import { CredentialVerificationError } from "../error";
import { JWK, jwtVerify } from "jose";
import { decodeVcdm2SdJwt, parseVcdm2Credential } from "../utils/vcdm2";
import { resolveVcdm2IssuerPublicKey } from "./vcdm2IssuerKey";

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
	return {
		async verify({ rawCredential }) {
			const decoded = decodeVcdm2SdJwt(rawCredential);
			if (!decoded) {
				return { success: false, error: CredentialVerificationError.VerificationProcessNotStarted };
			}

			// decodeVcdm2SdJwt is only a structural detector -- `@context`,
			// `type`, `issuer`, no `vct`. Without validating here, a validly
			// signed SD-JWT carrying those three members but otherwise
			// violating the VCDM 2.0 schema would be reported as verified.
			if (!parseVcdm2Credential(decoded.payload).success) {
				return { success: false, error: CredentialVerificationError.InvalidFormat };
			}

			const issuerPublicKey = await resolveVcdm2IssuerPublicKey(
				args, decoded.header, decoded.payload, { useIssClaim: true },
			);
			if (!issuerPublicKey.success) {
				return { success: false, error: issuerPublicKey.error };
			}

			try {
				await jwtVerify(decoded.issuerJwt, issuerPublicKey.value, {
					clockTolerance: args.context.clockTolerance,
				});
			} catch (err: unknown) {
				if (err instanceof Error && err.name === "JWTExpired") {
					return { success: false, error: CredentialVerificationError.ExpiredCredential };
				}
				return { success: false, error: CredentialVerificationError.InvalidSignature };
			}

			let holderJwk: JWK = {} as JWK;
			const cnf = decoded.payload?.cnf as { jwk?: JWK } | undefined;
			if (cnf?.jwk) holderJwk = cnf.jwk;

			return { success: true, value: { holderPublicKey: holderJwk } };
		},
	};
}
