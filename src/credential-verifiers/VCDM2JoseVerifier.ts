import { Context, CredentialVerifier, PublicKeyResolverEngineI, HttpClient } from "../interfaces";
import { CredentialVerificationError } from "../error";
import { JWK, jwtVerify } from "jose";
import { decodeEnvelopedVcdm2, parseVcdm2Credential } from "../utils/vcdm2";
import { resolveVcdm2IssuerPublicKey } from "./vcdm2IssuerKey";

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
	return {
		async verify({ rawCredential }) {
			const decoded = decodeEnvelopedVcdm2(rawCredential);
			if (!decoded) {
				return { success: false, error: CredentialVerificationError.VerificationProcessNotStarted };
			}

			// decodeEnvelopedVcdm2 accepts a token on its `typ` header alone,
			// so the payload is still unchecked here. Without this, a validly
			// signed token declaring `typ: vc+jwt` but missing required members
			// such as `credentialSubject` would be reported as verified.
			// Callers that invoke the verifier directly never reach the
			// parser's own validation.
			if (!parseVcdm2Credential(decoded.payload).success) {
				return { success: false, error: CredentialVerificationError.InvalidFormat };
			}

			const issuerPublicKey = await resolveVcdm2IssuerPublicKey(args, decoded.header, decoded.payload);
			if (!issuerPublicKey.success) {
				return { success: false, error: issuerPublicKey.error };
			}

			try {
				await jwtVerify(rawCredential as string, issuerPublicKey.value, {
					clockTolerance: args.context.clockTolerance,
				});
			} catch (err: unknown) {
				if (err instanceof Error && err.name === "JWTExpired") {
					return { success: false, error: CredentialVerificationError.ExpiredCredential };
				}
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
