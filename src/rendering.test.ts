import { assert, describe, it } from "vitest";
import { CredentialRenderingService } from "./rendering";
import { DOMParser } from "xmldom";
import fs from 'fs';
import path from 'path';

function dataUriToSvg(dataUri: string) {
	// Check if it starts with the SVG Data URI prefix
	if (dataUri.startsWith("data:image/svg+xml;utf8,")) {
		// Remove the prefix and decode the remaining part
		const svgString = decodeURIComponent(dataUri.replace("data:image/svg+xml;utf8,", ""));
		return svgString;
	} else if (dataUri.startsWith("data:image/svg+xml;base64,")) {
		// For base64-encoded SVGs, handle accordingly
		const base64Data = dataUri.replace("data:image/svg+xml;base64,", "");
		const svgString = atob(base64Data); // Decode base64 to plain text
		return svgString;
	} else {
		throw new Error("Invalid SVG Data URI format");
	}
}

function isValidSVG(dataUri: string) {

	const svgString = dataUriToSvg(dataUri);
	try {
		const parser = new DOMParser();
		const doc = parser.parseFromString(svgString, "image/svg+xml");
		// Check if the parsed document contains parser errors
		return doc.documentElement.nodeName !== "parsererror";
	} catch (e) {
		return false;
	}
}

const exampleCredentialPayload = {
	"cnf": {
		"jwk": {
			"crv": "P-256",
			"ext": true,
			"key_ops": [
				"verify"
			],
			"kty": "EC",
			"x": "lJ9Xd4t7nHpLdJRdhD5P6weX9KVDyefYKUrevWXjwm4",
			"y": "QcjdcG_EwXyCA0jWyS66cUVsGSrCZTRwTRp3avmjFKA"
		}
	},
	"vct": "urn:credential:vid",
	"jti": "urn:vid:b54b3fa2-4527-433f-b0ba-b3e7f4ad2826",
	"iat": 1736936437,
	"exp": 1736936,
	"iss": "http://wallet-enterprise-vid-issuer:8003",
	"sub": "vwGYXSfFHb3m9sVnIGbZ6aIpFPsy2YY-Yfthm8nBsXs",
	"family_name": "Doe",
	"given_name": "John",
	"birth_date": "1990-10-15T00:00:00.000Z",
	"issuing_authority": "PID:00001",
	"issuing_country": "GR",
	"document_number": "12313213",
	"issuance_date": "2025-01-15T10:20:37.707Z",
	"expiry_date": 1736936437
};


/**
 * Follows: https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-08.html#name-claim-metadata
 */
const exampleSdJwtVcMetadataClaimsAttribute = [
	{
		"path": ["given_name"],
		"display": [
			{
				"lang": "en-US",
				"label": "Given Name",
				"description": "The given name of the VID holder"
			}
		],
		"svg_id": "given_name"
	},
	{
		"path": ["family_name"],
		"display": [
			{
				"lang": "en-US",
				"label": "Family Name",
				"description": "The family name of the VID holder"
			}
		],
		"svg_id": "family_name"
	},
	{
		"path": ["birth_date"],
		"display": [
			{
				"lang": "en-US",
				"label": "Birth date",
				"description": "The birth date of the VID holder"
			}
		],
		"svg_id": "birth_date"
	},
	{
		"path": ["issuing_authority"],
		"display": [
			{
				"lang": "en-US",
				"label": "Issuing authority",
				"description": "The issuing authority of the VID credential"
			}
		],
		"svg_id": "issuing_authority"
	},
	{
		"path": ["issuance_date"],
		"display": [
			{
				"lang": "en-US",
				"label": "Issuance date",
				"description": "The date that the credential was issued"
			}
		],
		"svg_id": "issuance_date"
	},
	{
		"path": ["expiry_date"],
		"display": [
			{
				"lang": "en-US",
				"label": "Issuance date",
				"description": "The date that the credential will expire"
			}
		],
		"svg_id": "expiry_date"
	}
];

describe("The CredentialRendering", () => {
	const cr = CredentialRenderingService();

	it("can render credential in svg format", async () => {
		const svgPath = path.join(__dirname, "../assets/template.svg");
		const credentialSvgTemplate = fs.readFileSync(svgPath, { encoding: 'utf-8' });
		const dataUri = await cr.renderSvgTemplate({
			json: { ...exampleCredentialPayload },
			credentialImageSvgTemplate: credentialSvgTemplate,
			vcMetadataClaims: exampleSdJwtVcMetadataClaimsAttribute,
		});

		assert(dataUri !== null, "Svg not rendered");
		assert(isValidSVG(dataUri) == true, "Not valid generated datauri svg");
	});

	it("can render credential in svg format with filter", async () => {
		const svgPath = path.join(__dirname, "../assets/template.svg");
		const credentialSvgTemplate = fs.readFileSync(svgPath, { encoding: 'utf-8' });
		const dataUri = await cr.renderSvgTemplate({
			json: { ...exampleCredentialPayload },
			credentialImageSvgTemplate: credentialSvgTemplate,
			vcMetadataClaims: exampleSdJwtVcMetadataClaimsAttribute,
			filter: [
				["birth_date"]
			]
		});

		assert(dataUri !== null, "Svg not rendered");
		assert(isValidSVG(dataUri) == true, "Not valid generated datauri svg");
		fs.writeFileSync(path.join(__dirname, "../output/filtered.svg"), dataUriToSvg(dataUri), 'utf-8');
	});

	describe("with mdoc byte-string claims", () => {
		const template = '<svg xmlns="http://www.w3.org/2000/svg"><image href="{{portrait}}"/><text>{{name}}</text><text>{{seed}}</text></svg>';
		const claims = [
			{ path: ["org.iso.23220.1", "portrait"], svg_id: "portrait" },
			{ path: ["org.iso.23220.1", "family_name_unicode"], svg_id: "name" },
			{ path: ["org.iso.23220.1", "seed"], svg_id: "seed" },
		];
		const jpeg = [0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10];

		async function render(bytes: Uint8Array, filter?: string[][]) {
			const dataUri = await cr.renderSvgTemplate({
				json: { "org.iso.23220.1": { portrait: bytes, family_name_unicode: "De Bruijn", seed: new Uint8Array([1, 2, 3]) } },
				credentialImageSvgTemplate: template,
				vcMetadataClaims: claims,
				filter,
			});
			assert(dataUri !== null, "Svg not rendered");
			assert(isValidSVG(dataUri), "Not valid generated datauri svg");
			return dataUriToSvg(dataUri);
		}

		it("renders an image as a data URI", async () => {
			const svg = await render(new Uint8Array(jpeg));
			assert.include(svg, `href="data:image/jpeg;base64,${btoa(String.fromCharCode(...jpeg))}"`);
			assert.include(svg, "<text>De Bruijn</text>");
		});

		it("encodes only the claim's bytes when it is a view into a larger buffer", async () => {
			const buffer = new Uint8Array([0x01, 0x02, ...jpeg, 0x03]);
			const svg = await render(buffer.subarray(2, 2 + jpeg.length));
			assert.include(svg, `href="data:image/jpeg;base64,${btoa(String.fromCharCode(...jpeg))}"`);
		});

		it("leaves a byte string that is not an image as it was", async () => {
			const svg = await render(new Uint8Array(jpeg));
			assert.include(svg, "<text>1,2,3</text>");
		});

		it("does not reveal a portrait the filter excludes", async () => {
			const svg = await render(new Uint8Array(jpeg), [["org.iso.23220.1", "family_name_unicode"]]);
			assert.include(svg, 'href="-"');
		});
	});
})
