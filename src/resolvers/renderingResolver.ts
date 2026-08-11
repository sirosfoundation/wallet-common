import type { RenderingCallback } from "../types";
import { matchDisplayByLocale } from "../utils/matchLocalizedDisplay";
import type { TypeDisplayEntry } from "../schemas/SdJwtVcTypeMetadataSchema";
import type { CredentialConfigurationSupported } from "../schemas/CredentialConfigurationSupportedSchema";

type IssuerDisplayEntry =
	NonNullable<
		NonNullable<CredentialConfigurationSupported["credential_metadata"]>["display"]
	>[number];

type RenderingResolverOptions = {
	credentialDisplayArray?: TypeDisplayEntry[];
	issuerDisplayArray?: IssuerDisplayEntry[];
};

/**
 * Resolves the display rendering (background color, text color, logo) for a
 * credential.
 */
export function renderingResolver({
	credentialDisplayArray,
	issuerDisplayArray,
}: RenderingResolverOptions): RenderingCallback {
	return async (preferredLangs: string[] = ["en-US"]) => {
		const credential = matchDisplayByLocale(credentialDisplayArray, preferredLangs);
		const issuer = matchDisplayByLocale(issuerDisplayArray, preferredLangs);

		const simple = credential?.rendering?.simple;

		const backgroundColor = simple?.background_color ?? issuer?.background_color;
		const textColor = simple?.text_color ?? issuer?.text_color;
		const logo = simple?.logo?.uri ?? issuer?.logo?.uri;

		if (backgroundColor == null && textColor == null && logo == null) {
			return null;
		}

		return { backgroundColor, textColor, logo };
	};
}
