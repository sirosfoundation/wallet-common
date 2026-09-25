import type { JWK } from "jose";
import { Context, CredentialVerifier, PublicKeyResolverEngineI, HttpClient } from "../interfaces";
import { CredentialVerificationError } from "../error";
import type { DataIntegrityProof } from "../schemas/Vcdm2CredentialSchema";
import {
	coerceCredentialObject,
	isVcdm2Credential,
	parseVcdm2Credential,
	proofsOf,
} from "../utils/vcdm2";
import { didKeyToJwk } from "../utils/dataIntegrity/multibase";
import {
	resolveCryptosuite,
	verifyDataIntegrityProof,
} from "../utils/dataIntegrity/verifyDataIntegrityProof";

/**
 * Verifier for W3C VCDM 2.0 credentials secured with an embedded Data
 * Integrity proof (OpenID4VCI format `ldp_vc`).
 *
 * A credential with several proofs is accepted when *any* one of them
 * verifies, matching VC-DI's treatment of a proof set. Proof *chains*
 * (`previousProof`) are not evaluated as chains.
 */
export function VCDM2LdpVerifier(args: { context: Context, pkResolverEngine: PublicKeyResolverEngineI, httpClient: HttpClient }): CredentialVerifier {

	const resolveVerificationMethodKey = async (verificationMethod: string): Promise<JWK | null> => {
		// did:key encodes the key in the identifier, so no resolution needed.
		if (verificationMethod.startsWith("did:key:")) {
			try {
				return didKeyToJwk(verificationMethod);
			} catch {
				return null;
			}
		}

		const resolution = await args.pkResolverEngine.resolve({ identifier: verificationMethod });
		if (resolution.success) return resolution.value.jwk;

		// Some issuers name a fragment on a controller document; retry
		// against the bare controller identifier.
		const withoutFragment = verificationMethod.split("#")[0];
		if (withoutFragment !== verificationMethod) {
			const fallback = await args.pkResolverEngine.resolve({ identifier: withoutFragment });
			if (fallback.success) return fallback.value.jwk;
		}

		return null;
	};

	return {
		async verify({ rawCredential }) {
			const candidate = coerceCredentialObject(rawCredential);
			if (candidate === null || !isVcdm2Credential(candidate)) {
				return { success: false, error: CredentialVerificationError.VerificationProcessNotStarted };
			}

			const parsed = parseVcdm2Credential(candidate);
			if (!parsed.success) {
				return { success: false, error: CredentialVerificationError.InvalidFormat };
			}
			const credential = parsed.value;

			const proofs: DataIntegrityProof[] = proofsOf(credential);
			if (proofs.length === 0) {
				return { success: false, error: CredentialVerificationError.MissingDataIntegrityProof };
			}

			// Remember the most specific failure so a credential with several
			// proofs reports something more useful than "invalid signature"
			// when the real problem is an unsupported suite.
			let lastError: CredentialVerificationError = CredentialVerificationError.InvalidSignature;

			for (const proof of proofs) {
				const cryptosuite = resolveCryptosuite(proof);
				if (!cryptosuite) {
					lastError = CredentialVerificationError.UnsupportedCryptosuite;
					continue;
				}

				const publicKey = await resolveVerificationMethodKey(proof.verificationMethod);
				if (!publicKey) {
					lastError = CredentialVerificationError.CannotResolveIssuerPublicKey;
					continue;
				}

				const result = await verifyDataIntegrityProof({
					credential,
					proof,
					publicKey,
					subtle: args.context.subtle,
					httpClient: args.httpClient,
				});

				if (result.success) {
					// Data Integrity credentials carry no holder binding of
					// their own; an empty JWK matches what JWTVCJSONVerifier
					// returns when `cnf` is absent.
					return { success: true, value: { holderPublicKey: {} as JWK } };
				}

				switch (result.failure.kind) {
					case "unsupported-cryptosuite":
						lastError = CredentialVerificationError.UnsupportedCryptosuite;
						break;
					case "canonicalization-failed":
						lastError = CredentialVerificationError.CanonicalizationFailed;
						break;
					case "context-unresolvable":
						lastError = CredentialVerificationError.UnresolvableJsonLdContext;
						break;
					case "invalid-proof":
						lastError = CredentialVerificationError.InvalidFormat;
						break;
					default:
						lastError = CredentialVerificationError.InvalidSignature;
				}
			}

			return { success: false, error: lastError };
		},
	};
}
