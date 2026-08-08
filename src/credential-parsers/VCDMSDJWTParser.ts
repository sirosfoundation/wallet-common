/**
 * Parser for W3C VCDM 2.0 credentials secured with SD-JWT.
 *
 * DIIP v5 requires support for "Securing JSON-LD Verifiable Credentials with SD-JWT" as specified
 * in VC-JOSE-COSE. There the unsecured credential *is* the JWT Claims Set: `@context`, `type`,
 * `issuer`, `validFrom`, `validUntil` and `credentialSubject` sit at the top level, the `vc` and
 * `vp` claim names are forbidden, and there is no `vct`.
 *
 * The SD-JWT envelope, holder binding and signature verification are identical to SD-JWT VC, so
 * only the payload vocabulary is handled here — `SDJWTVCVerifier` verifies both.
 *
 * @see https://www.w3.org/TR/2025/REC-vc-jose-cose-20250515/#secure-with-sd-jwt
 */

import { SDJwt } from "@sd-jwt/core";
import type { HasherAndAlg } from "@sd-jwt/types";
import { CredentialParsingError } from "../error";
import { Context, CredentialParser, HttpClient } from "../interfaces";
import { MetadataWarning, TypeMetadataResult, VerifiableCredentialFormat } from "../types";
import { CredentialRenderingService } from "../rendering";
import { CustomCredentialSvg } from "../functions/CustomCredentialSvg";
import { getIssuerMetadata } from "../utils/getIssuerMetadata";
import { convertOpenid4vciToSdjwtvcClaims } from "../functions/convertOpenid4vciToSdjwtvcClaims";
import { dataUriResolver } from "../resolvers/dataUriResolver";
import { friendlyNameResolver } from "../resolvers/friendlyNameResolver";
import { isW3CVcdmSdJwtPayload } from "../utils/detectCredentialFormat";
import { ValidityClaims, extractValidityInfo } from "../utils/credentialValidity";
import type { IAuthZENClient } from "../authzen/AuthZENClient";

const FALLBACK_NAME = "Verifiable Credential";

/**
 * A VCDM `issuer` is either an identifier string or an object with an `id`.
 */
function resolveIssuerId(claims: Record<string, unknown>): string | null {
	const issuer = claims.issuer;
	if (typeof issuer === "string") {
		return issuer;
	}
	if (typeof issuer === "object" && issuer !== null && typeof (issuer as { id?: unknown }).id === "string") {
		return (issuer as { id: string }).id;
	}
	// JOSE-registered `iss` is permitted alongside, and is the only identifier in some profiles.
	return typeof claims.iss === "string" ? claims.iss : null;
}

/**
 * A VCDM `issuer` object may carry a human-readable `name`.
 */
function resolveIssuerName(claims: Record<string, unknown>, fallback: string): string {
	const issuer = claims.issuer;
	if (typeof issuer === "object" && issuer !== null) {
		const name = (issuer as { name?: unknown }).name;
		if (typeof name === "string") {
			return name;
		}
	}
	return fallback;
}

/** Normalise a VCDM property that may be a single value or an array. */
function toStringArray(value: unknown): string[] {
	if (typeof value === "string") {
		return [value];
	}
	if (Array.isArray(value)) {
		return value.filter((entry): entry is string => typeof entry === "string");
	}
	return [];
}

export function VCDMSDJWTParser(args: { context: Context, httpClient: HttpClient, authzenClient?: IAuthZENClient }): CredentialParser {
	const encoder = new TextEncoder();

	const hasherAndAlgorithm: HasherAndAlg = {
		hasher: (data: string | ArrayBuffer, alg: string) => {
			const encoded = typeof data === 'string' ? encoder.encode(data) : new Uint8Array(data);
			return args.context.subtle.digest(alg, encoded).then((v) => new Uint8Array(v));
		},
		alg: 'sha-256',
	};

	const cr = CredentialRenderingService();
	const renderer = CustomCredentialSvg({ httpClient: args.httpClient });

	function canParseVcdmSdJwt(raw: unknown): raw is string {
		return typeof raw === "string" && raw.includes(".") && isW3CVcdmSdJwtPayload(raw);
	}

	return {
		async parse({ rawCredential, credentialIssuer }) {
			if (!canParseVcdmSdJwt(rawCredential)) {
				return { success: false, error: CredentialParsingError.UnsupportedFormat };
			}

			const warnings: MetadataWarning[] = [];

			const parsedClaims = await (async () => {
				try {
					const parsedSdJwt = await SDJwt.fromEncode(rawCredential, hasherAndAlgorithm.hasher);
					return await parsedSdJwt.getClaims(hasherAndAlgorithm.hasher) as Record<string, unknown>;
				}
				catch {
					return null;
				}
			})();

			if (!parsedClaims) {
				return { success: false, error: CredentialParsingError.CouldNotParse };
			}

			// VC-JOSE-COSE §3.2.1: "The JWT Claim Names `vc` and `vp` MUST NOT be present."
			if ("vc" in parsedClaims || "vp" in parsedClaims) {
				return { success: false, error: CredentialParsingError.InvalidSdJwtVcPayload };
			}

			const context = toStringArray(parsedClaims["@context"]);
			if (context.length === 0) {
				return { success: false, error: CredentialParsingError.InvalidSdJwtVcPayload };
			}

			const issuerId = resolveIssuerId(parsedClaims);
			if (!issuerId) {
				return { success: false, error: CredentialParsingError.InvalidSdJwtVcPayload };
			}

			const { metadata: issuerMetadata } = await getIssuerMetadata(
				args.httpClient, issuerId, warnings, true, args.authzenClient,
			);

			const credentialIssuerMetadata = credentialIssuer?.credentialConfigurationId
				? issuerMetadata?.credential_configurations_supported?.[credentialIssuer.credentialConfigurationId]
				: undefined;

			// A VCDM credential carries no VCT type metadata document, so display information comes
			// from the issuer's credential configuration, falling back to the credential's own `name`.
			let TypeMetadata: TypeMetadataResult = {};
			if (credentialIssuerMetadata?.credential_metadata?.claims) {
				const convertedClaims = convertOpenid4vciToSdjwtvcClaims(credentialIssuerMetadata.credential_metadata.claims);
				if (convertedClaims?.length) {
					TypeMetadata = { claims: convertedClaims };
				}
			}

			const credentialName = typeof parsedClaims.name === "string" ? parsedClaims.name : FALLBACK_NAME;

			const friendlyName = friendlyNameResolver({
				issuerDisplayArray: credentialIssuerMetadata?.credential_metadata?.display,
				fallbackName: credentialName,
			});

			const dataUri = dataUriResolver({
				httpClient: args.httpClient,
				customRenderer: renderer,
				signedClaims: parsedClaims,
				issuerDisplayArray: credentialIssuerMetadata?.credential_metadata?.display,
				vcRenderer: cr,
				vcMetadataClaims: TypeMetadata.claims,
				fallbackName: credentialName,
			});

			return {
				success: true,
				value: {
					signedClaims: parsedClaims,
					metadata: {
						credential: {
							format: VerifiableCredentialFormat.W3C_VCDM_SDJWT,
							type: toStringArray(parsedClaims.type),
							context,
							TypeMetadata,
							image: { dataUri },
							name: friendlyName,
						},
						issuer: {
							id: issuerId,
							name: resolveIssuerName(parsedClaims, issuerId),
						},
					},
					validityInfo: {
						...extractValidityInfo(parsedClaims as ValidityClaims),
					},
					warnings: warnings.length > 0 ? warnings : undefined,
				},
			};
		},
	};
}
