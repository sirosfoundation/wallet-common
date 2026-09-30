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
	coerceCredentialObject,
	extractVcdm2ValidityInfo,
	isVcdm2Credential,
	issuerIdentifier,
	validatedIssuerDisplayName,
	validatedIssuerIdentifier,
	parseVcdm2Credential,
	primaryCredentialType,
	toTypeArray,
} from "../utils/vcdm2";
import type { IAuthZENClient } from "../authzen/AuthZENClient";

/**
 * Parser for W3C VCDM 2.0 credentials secured with an embedded Data Integrity
 * proof (OpenID4VCI format `ldp_vc`).
 *
 * Unlike every other format the wallet handles, these are JSON-LD objects
 * rather than compact token strings, so they arrive either already decoded or
 * as their JSON serialisation from storage.
 *
 * Parsing deliberately does not require a `proof`: an unsigned credential
 * still displays, and it is the verifier's job to refuse it. That keeps a
 * missing proof reportable as a verification failure rather than an opaque
 * "unsupported format".
 */
export function VCDM2LdpParser(args: { context: Context, httpClient: HttpClient, authzenClient?: IAuthZENClient }): CredentialParser {

	return {
		async parse({ rawCredential, credentialIssuer }) {

			const candidate = coerceCredentialObject(rawCredential);
			if (candidate === null || !isVcdm2Credential(candidate)) {
				return {
					success: false,
					error: CredentialParsingError.UnsupportedFormat,
				};
			}

			const credentialResult = parseVcdm2Credential(candidate);
			if (!credentialResult.success) {
				return {
					success: false,
					error: CredentialParsingError.InvalidVcdm2Credential,
				};
			}
			const credential = credentialResult.value;

			const warnings: MetadataWarning[] = [];
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
							format: VerifiableCredentialFormat.LDP_VC,
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
						...extractVcdm2ValidityInfo(credential),
					},
					warnings: warnings.length > 0 ? warnings : undefined,
				},
			};
		},
	};
}
