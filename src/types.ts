import { CredentialParsingError } from "./error";
import { ClaimMetadataEntry } from "./schemas/SdJwtVcTypeMetadataSchema";

export enum VerifiableCredentialFormat {
	VC_SDJWT = "vc+sd-jwt",
	DC_SDJWT = "dc+sd-jwt",
	MSO_MDOC = "mso_mdoc",
	JWT_VC_JSON = "jwt_vc_json",

	// W3C VCDM 2.0 secured with an enveloping JOSE proof (VC-JOSE-COSE).
	// The JWT payload *is* the credential — there is no `vc` wrapper claim,
	// which is what distinguishes it from JWT_VC_JSON (VCDM 1.1).
	VCDM2_JOSE = "vc+jwt",

	// W3C VCDM 2.0 secured with an embedded Data Integrity proof.
	// The credential is a JSON-LD object carrying its own `proof` member.
	LDP_VC = "ldp_vc"
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

export type CredentialRenderingInfo = {
	backgroundColor?: string;
	textColor?: string;
	logo?: string;
};

export type RenderingCallback = (
	preferredLangs?: string[]
) => Promise<CredentialRenderingInfo | null>;


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
			rendering: RenderingCallback,
		} | {
			format: VerifiableCredentialFormat.MSO_MDOC,
			doctype: string,
			name: FriendlyNameCallback,
			TypeMetadata: TypeMetadataResult,
			image: {
				dataUri: ImageDataUriCallback,
			},
			rendering: RenderingCallback,
		} | {
			format: VerifiableCredentialFormat.JWT_VC_JSON,
			type: string[],
			name: FriendlyNameCallback,
			TypeMetadata: TypeMetadataResult,
			image: {
				dataUri: ImageDataUriCallback,
			},
			rendering: RenderingCallback,
		} | {
			// W3C VCDM 2.0, either enveloped in a JWS (VC-JOSE-COSE) or
			// carrying an embedded Data Integrity proof. Both are described
			// by the credential's `type` array, as VCDM 1.1 is — neither has
			// an SD-JWT `vct` or an mdoc `doctype`.
			format: VerifiableCredentialFormat.VCDM2_JOSE | VerifiableCredentialFormat.LDP_VC,
			type: string[],
			name: FriendlyNameCallback,
			TypeMetadata: TypeMetadataResult,
			image: {
				dataUri: ImageDataUriCallback,
			},
			rendering: RenderingCallback,
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
