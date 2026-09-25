import { CredentialParsingError } from "../error";
import { Context, CredentialParser, HttpClient } from "../interfaces";
import { MetadataWarning, TypeMetadataResult, VerifiableCredentialFormat } from "../types";
import { Vcdm2JoseHeaderSchema } from "../schemas/Vcdm2CredentialSchema";
import { CustomCredentialSvg } from "../functions/CustomCredentialSvg";
import { getIssuerMetadata } from "../utils/getIssuerMetadata";
import { convertOpenid4vciToSdjwtvcClaims } from "../functions/convertOpenid4vciToSdjwtvcClaims";
import { dataUriResolver } from "../resolvers/dataUriResolver";
import { friendlyNameResolver } from "../resolvers/friendlyNameResolver";
import { renderingResolver } from "../resolvers/renderingResolver";
import {
	decodeEnvelopedVcdm2,
	extractVcdm2ValidityInfo,
	issuerIdentifier,
	validatedIssuerDisplayName,
	validatedIssuerIdentifier,
	parseVcdm2Credential,
	primaryCredentialType,
	toTypeArray,
} from "../utils/vcdm2";
import type { IAuthZENClient } from "../authzen/AuthZENClient";

/**
 * Parser for W3C VCDM 2.0 credentials secured with an enveloping JOSE proof
 * (VC-JOSE-COSE).
 *
 * The distinguishing feature versus JWT_VC_JSON (VCDM 1.1) is that the JWT
 * payload *is* the credential — there is no `vc` wrapper claim — so this must
 * be registered ahead of JWTVCJSONParser, which would otherwise reject the
 * credential outright for lacking that wrapper.
 */
export function VCDM2JoseParser(args: { context: Context, httpClient: HttpClient, authzenClient?: IAuthZENClient }): CredentialParser {

	return {
		async parse({ rawCredential, credentialIssuer }) {

			const decoded = decodeEnvelopedVcdm2(rawCredential);
			if (!decoded) {
				return {
					success: false,
					error: CredentialParsingError.UnsupportedFormat,
				};
			}

			const headerResult = Vcdm2JoseHeaderSchema.safeParse(decoded.header);
			if (!headerResult.success) {
				return {
					success: false,
					error: CredentialParsingError.CouldNotParse,
				};
			}

			const credentialResult = parseVcdm2Credential(decoded.payload);
			if (!credentialResult.success) {
				return {
					success: false,
					error: CredentialParsingError.InvalidVcdm2Credential,
				};
			}
			const credential = credentialResult.value;

			const warnings: MetadataWarning[] = [];

			// A JWT-enveloped credential may still carry the registered JWT
			// claims alongside; where present they win, since a JWT verifier
			// enforces those rather than validFrom/validUntil.
			const jwtClaims = {
				exp: typeof decoded.payload?.exp === "number" ? decoded.payload.exp : undefined,
				iat: typeof decoded.payload?.iat === "number" ? decoded.payload.iat : undefined,
				nbf: typeof decoded.payload?.nbf === "number" ? decoded.payload.nbf : undefined,
			};

			const issuerId = issuerIdentifier(credential.issuer);

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

			// Prefer the credential's own most specific type over a generic
			// fallback, so an unconfigured issuer still yields a usable label.
			const fallbackName = primaryCredentialType(credential.type) ?? "Verifiable Credential";

			const friendlyName = friendlyNameResolver({
				issuerDisplayArray,
				fallbackName,
			});

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
					signedClaims: credential as Record<string, unknown>,
					metadata: {
						credential: {
							format: VerifiableCredentialFormat.VCDM2_JOSE,
							type: toTypeArray(credential.type),
							TypeMetadata,
							image: {
								dataUri: dataUri,
							},
							rendering: rendering,
							name: friendlyName,
						},
						issuer: {
							id: validatedIssuerIdentifier(credential.issuer),
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
