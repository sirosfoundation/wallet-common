import { CredentialParsingError } from "./error";
import { ClaimMetadataEntry } from "./schemas/SdJwtVcTypeMetadataSchema";

export enum VerifiableCredentialFormat {
	VC_SDJWT = "vc+sd-jwt",
	DC_SDJWT = "dc+sd-jwt",
	MSO_MDOC = "mso_mdoc",
	JWT_VC_JSON = "jwt_vc_json",
	/**
	 * A W3C VCDM 2.0 credential secured with SD-JWT, as required by DIIP v5.
	 *
	 * VC-JOSE-COSE §3.2.1 gives these the `typ` header `vc+sd-jwt` — the same string as the
	 * legacy SD-JWT VC format above — so this member carries a distinct value and the two are
	 * told apart by payload shape instead: a `vct` claim means SD-JWT VC, while `@context`
	 * without a `vct` means VCDM 2.0. See `detectCredentialFormat`.
	 */
	W3C_VCDM_SDJWT = "w3c_vcdm_sd_jwt",
}

export type CredentialIssuer = {
	id: string; // must have the value of "iss" attribute of an SD-JWT VC credential
	name: string;

	// ...other metadata
}

export type CredentialClaims = Record<string, unknown>;

export type CustomResult<T, E> = { success: true; value: T } | { success: false; error: E };

export type ParserResult =
	| { success: true; value: ParsedCredential }
	| { success: false; error: CredentialParsingError };

export type CredentialPayload = {
	iss: string;
	vct: string;
	[key: string]: unknown;
};

export type MetadataError = {
	error: CredentialParsingError;
};

export type MetadataWarning = {
	code: CredentialParsingError;
};

export type CredentialClaimPath = Array<string>;

export type FriendlyNameCallback = (
	preferredLangs?: string[]
) => Promise<string | null>;

export type ImageDataUriCallback = (
	filter?: Array<CredentialClaimPath>,
	preferredLangs?: string[]
) => Promise<string | null>;


export type AugmentedClaimMetadataEntry = ClaimMetadataEntry & {
	required?: boolean;
};

export type TypeMetadataResult = {
	claims?: Array<AugmentedClaimMetadataEntry>;
};

export type ParsedCredential = {
	metadata: {
		credential: {
			format: VerifiableCredentialFormat.VC_SDJWT | VerifiableCredentialFormat.DC_SDJWT,
			vct: string,
			name: FriendlyNameCallback,
			TypeMetadata: TypeMetadataResult,
			image: {
				dataUri: ImageDataUriCallback,
			},
		} | {
			format: VerifiableCredentialFormat.MSO_MDOC,
			doctype: string,
			name: FriendlyNameCallback,
			TypeMetadata: TypeMetadataResult,
			image: {
				dataUri: ImageDataUriCallback,
			},
		} | {
			format: VerifiableCredentialFormat.JWT_VC_JSON,
			type: string[],
			name: FriendlyNameCallback,
			TypeMetadata: TypeMetadataResult,
			image: {
				dataUri: ImageDataUriCallback,
			},
		} | {
			format: VerifiableCredentialFormat.W3C_VCDM_SDJWT,
			/** The credential's `type` array, e.g. `["VerifiableCredential", "OpenBadgeCredential"]`. */
			type: string[],
			/** The JSON-LD `@context` the credential declares. */
			context: string[],
			name: FriendlyNameCallback,
			TypeMetadata: TypeMetadataResult,
			image: {
				dataUri: ImageDataUriCallback,
			},
		},
		issuer: CredentialIssuer,
	},
	validityInfo: {
		validUntil?: Date,
		validFrom?: Date,
		signed?: Date,
	}
	signedClaims: CredentialClaims,
	warnings?: Array<MetadataWarning>;
};
