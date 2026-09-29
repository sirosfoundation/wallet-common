import jsonpointer from 'jsonpointer';
import { formatDate } from './functions/formatDate';
import { CredentialRendering } from './interfaces';
import { escapeSVG } from './utils/escapeSVG';
import { CredentialClaimPath } from './types';
import { toBase64 } from './utils/util';

// Image signatures an mdoc byte-string claim (e.g. an ISO 18013-5 / 23220
// `portrait`) is recognised by.
const imageSignatures: Array<[string, number[]]> = [
	['image/jpeg', [0xff, 0xd8, 0xff]],
	['image/png', [0x89, 0x50, 0x4e, 0x47]],
	['image/jp2', [0x00, 0x00, 0x00, 0x0c, 0x6a, 0x50, 0x20, 0x20]],
];

/**
 * An mdoc claim declared as a bstr is decoded to a Uint8Array, which a
 * template placeholder would otherwise stringify as "255,216,255,...".
 * An image becomes a data URI, so `<image href="{{portrait}}"/>` shows it;
 * any other byte string is left for the caller to render as before.
 */
function imageDataUri(value: unknown): string | undefined {
	if (!(value instanceof Uint8Array)) {
		return undefined;
	}
	const match = imageSignatures.find(([, signature]) => signature.every((b, i) => value[i] === b));
	if (!match) {
		return undefined;
	}
	// slice(): cbor decoders hand out views into a larger buffer, and
	// toBase64 encodes a view's whole underlying buffer.
	return `data:${match[0]};base64,${toBase64(value.slice())}`;
}

export function CredentialRenderingService(): CredentialRendering {
	const renderSvgTemplate = async ({ json, credentialImageSvgTemplate, vcMetadataClaims, filter }: { json: any, credentialImageSvgTemplate: string, vcMetadataClaims: any, filter?: Array<CredentialClaimPath> }) => {

		let svgContent = null;
		try {
			svgContent = credentialImageSvgTemplate;
		} catch (error) {
			return null; // Return null if fetching fails
		}

		if (svgContent) {
			// Build pathMap from credentialHeader.vctm.claims
			const pathMap = (vcMetadataClaims ?? []).reduce((acc: any, claim: any) => {
				if (claim.svg_id && claim.path) {
					acc[claim.svg_id] = claim.path;
				}
				return acc;
			}, {});

			// Regular expression to match {{svg_id}} placeholders
			const regex = /{{([^}]+)}}/g;
			const replacedSvgText = svgContent.replace(regex, (_match, svgId) => {
				// Retrieve the path array for the current svgId from pathMap
				const pathArray = pathMap[svgId];

				if (Array.isArray(pathArray) && filter && !filter.map(f => f.join('.')).includes(pathArray.join('.'))) {
					return '-';
				}
				// If pathArray exists, convert it to a JSON pointer path
				if (Array.isArray(pathArray)) {
					const jsonPointerPath = `/${pathArray.join('/')}`;

					// Retrieve the value from beautifiedForm using jsonpointer
					const raw = jsonpointer.get(json, jsonPointerPath);
					const imageUri = imageDataUri(raw);
					if (imageUri) {
						return imageUri;
					}
					let value = escapeSVG(raw);

					if (value !== undefined) {
						value = formatDate(value, 'date');
						return value;
					}
				}
				return '-';
			});
			const dataUri = `data:image/svg+xml;utf8,${encodeURIComponent(replacedSvgText)}`;
			return dataUri; // Return the data URI for the SVG
		}

		return null;
	};

	return {
		renderSvgTemplate,
	}
}
