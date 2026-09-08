import { SDJwt } from "@sd-jwt/core";
import type { HasherAndAlg } from "@sd-jwt/types";
import { CredentialParsingError } from "../error";
import { Context, CredentialParser, HttpClient } from "../interfaces";
import { MetadataWarning, TypeMetadataResult, VerifiableCredentialFormat } from "../types";
import { CustomCredentialSvg } from "../functions/CustomCredentialSvg";
import { getIssuerMetadata } from "../utils/getIssuerMetadata";
import { convertOpenid4vciToSdjwtvcClaims } from "../functions/convertOpenid4vciToSdjwtvcClaims";
import { dataUriResolver } from "../resolvers/dataUriResolver";
import { friendlyNameResolver } from "../resolvers/friendlyNameResolver";
import { renderingResolver } from "../resolvers/renderingResolver";
import {
	decodeVcdm2SdJwt,
	extractVcdm2ValidityInfo,
	parseVcdm2Credential,
	primaryCredentialType,
	toTypeArray,
	validatedIssuerDisplayName,
	validatedIssuerIdentifier,
} from "../utils/vcdm2";
import type { IAuthZENClient } from "../authzen/AuthZENClient";

/**
 * Parser for a W3C VCDM 2.0 credential carried inside an SD-JWT, which is how
 * DIIP v5 specifies VCDM 2.0.
 *
 * The issuer-signed JWT's payload is the credential itself. It is *not* an
 * SD-JWT VC: there is no `vct`, because this is a plain SD-JWT whose claims
 * happen to be a verifiable credential. OpenID4VCI advertises it as
 * `vc+sd-jwt`, the same identifier legacy SD-JWT VC uses, so the two are told
 * apart by the payload — anything carrying a `vct` is left to SDJWTVCParser.
 *
 * This must therefore be registered *ahead* of SDJWTVCParser, which would
 * otherwise claim the credential and reject it for the missing `vct`.
 *
 * DIIP v5 discloses every claim, so in practice there are no disclosures and
 * the credential is a JWT with a trailing `~`. Disclosures are still expanded
 * where present, so a partially disclosed credential parses correctly.
 */
export function VCDM2SdJwtParser(args: { context: Context, httpClient: HttpClient, authzenClient?: IAuthZENClient }): CredentialParser {
	const encoder = new TextEncoder();

	const hasherAndAlgorithm: HasherAndAlg = {
		hasher: (data: string | ArrayBuffer, alg: string) => {
			/* v8 ignore next -- @sd-jwt/core only ever hands this disclosure strings */
			const encoded = typeof data === "string" ? encoder.encode(data) : new Uint8Array(data);
			return args.context.subtle.digest(alg, encoded).then((v) => new Uint8Array(v));
		},
		alg: "sha-256",
	};

	return {
		async parse({ rawCredential, credentialIssuer }) {

			const decoded = decodeVcdm2SdJwt(rawCredential);
			if (!decoded) {
				return {
					success: false,
					error: CredentialParsingError.UnsupportedFormat,
				};
			}

			// Expand any disclosures, so a partially disclosed credential
			// yields its full claim set rather than the digests.
			let claims: Record<string, unknown>;
			try {
				const parsed = await SDJwt.fromEncode(rawCredential as string, hasherAndAlgorithm.hasher);
				claims = await parsed.getClaims(hasherAndAlgorithm.hasher) as Record<string, unknown>;
			} catch {
				return {
					success: false,
					error: CredentialParsingError.CouldNotParse,
				};
			}

			const credentialResult = parseVcdm2Credential(claims);
			if (!credentialResult.success) {
				return {
					success: false,
					error: CredentialParsingError.InvalidVcdm2Credential,
				};
			}
			const credential = credentialResult.value;

			const warnings: MetadataWarning[] = [];

			// A credential of this shape may carry the registered JWT claims
			// alongside; where present they win, as they do for the enveloped
			// form, since a JWT verifier enforces those.
			const jwtClaims = {
				exp: typeof claims.exp === "number" ? claims.exp : undefined,
				iat: typeof claims.iat === "number" ? claims.iat : undefined,
				nbf: typeof claims.nbf === "number" ? claims.nbf : undefined,
			};

			// `iss` is the JWT's own issuer claim; fall back to the
			// credential's `issuer` member when the issuer omits it.
			const issuerId = typeof claims.iss === "string"
				? claims.iss
				: validatedIssuerIdentifier(credential.issuer);

			const { metadata: issuerMetadata } = await getIssuerMetadata(
				args.httpClient, issuerId, warnings, true, args.authzenClient,
			);

			const credentialIssuerMetadata = credentialIssuer?.credentialConfigurationId
				? issuerMetadata?.credential_configurations_supported?.[credentialIssuer.credentialConfigurationId]
				: undefined;

			let TypeMetadata: TypeMetadataResult = {};
			if (credentialIssuerMetadata?.credential_metadata?.claims) {
				const convertedClaims = convertOpenid4vciToSdjwtvcClaims(credentialIssuerMetadata.credential_metadata.claims);
				if (convertedClaims?.length) {
					TypeMetadata = { claims: convertedClaims };
				}
			}

			const issuerDisplayArray = credentialIssuerMetadata?.credential_metadata?.display;
			const renderer = CustomCredentialSvg({ httpClient: args.httpClient });

			const fallbackName = primaryCredentialType(credential.type) ?? "Verifiable Credential";

			const friendlyName = friendlyNameResolver({ issuerDisplayArray, fallbackName });

			const dataUri = dataUriResolver({
				httpClient: args.httpClient,
				customRenderer: renderer,
				issuerDisplayArray,
				fallbackName,
			});

			const rendering = renderingResolver({ issuerDisplayArray });

			return {
				success: true,
				value: {
					signedClaims: claims,
					metadata: {
						credential: {
							format: VerifiableCredentialFormat.VCDM2_SDJWT,
							type: toTypeArray(credential.type),
							TypeMetadata,
							image: {
								dataUri: dataUri,
							},
							rendering: rendering,
							name: friendlyName,
						},
						issuer: {
							id: issuerId,
							name: validatedIssuerDisplayName(credential.issuer),
						},
					},
					validityInfo: {
						...extractVcdm2ValidityInfo(credential, jwtClaims),
					},
					warnings: warnings.length > 0 ? warnings : undefined,
				},
			};
		},
	};
}
