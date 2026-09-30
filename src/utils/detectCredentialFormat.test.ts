import { base64url } from 'jose';
import { describe, expect, it } from 'vitest';
import { VerifiableCredentialFormat } from '../types';
import { detectCredentialFormat, detectSdJwtVariant, isMdoc, isJwtVcJson, isSdJwt } from './detectCredentialFormat';
import { b64url as enc, bytesToB64Url, unsignedSdJwt, VCDM2_CONTEXT } from '../testFixtures/vcdm2TestSupport';

const ISSUER = "did:example:issuer";

const vcdm2Credential = {
	"@context": [VCDM2_CONTEXT],
	type: ["VerifiableCredential", "DiplomaCredential"],
	issuer: "did:example:issuer",
	credentialSubject: { id: "did:example:subject", degree: "BSc" },
};

function envelopedVcdm2(payload: object = vcdm2Credential): string {
	return `${enc({ alg: "ES256", typ: "vc+jwt" })}.${enc(payload)}.sig`;
}

function vcdm11Jwt(): string {
	return `${enc({ alg: "ES256" })}.${enc({ vc: { type: ["VerifiableCredential"] } })}.sig`;
}

const credentialBody = {
	"@context": [VCDM2_CONTEXT],
	type: ["VerifiableCredential", "StudentCardCredential"],
	issuer: "https://mbob.issuer.dev.eduwallet.nl",
	credentialSubject: { id: "did:example:subject", given_name: "Alice" },
};


describe('isMdoc', () => {
	it('returns true for CBOR tag 0xA2 0x6A', () => {
		const raw = "omoAAHsiaGVsbG8iOiAid29ybGQifQ=="; // Base64url starting with [0xa2, 0x6a, 0x00, 0x00]
		expect(isMdoc(raw)).toBe(true);
	});

	it('returns true for CBOR tag 0xB9 0x00', () => {
		const raw = "uQAAAAHsiaGVsbG8iOiAid29ybGQifQ=="; // Base64url starting with [0xb9, 0x00, 0x00, 0x00]

		expect(isMdoc(raw)).toBe(true);
	});

	it('returns false for non-CBOR data', () => {
		const raw = base64url.encode(new Uint8Array([0x00, 0x00, 0x00, 0x00]));
		expect(isMdoc(raw)).toBe(false);
	});

	it('returns false for invalid base64url', () => {
		expect(isMdoc('!!!invalid!!!')).toBe(false);
	});
});

describe('isSdJwt', () => {
	it('returns true for a valid SD-JWT (3-part JWT followed by ~)', () => {
		expect(isSdJwt('header.payload.signature~disclosure1~')).toBe(true);
	});

	it('returns false when there is no tilde', () => {
		expect(isSdJwt('header.payload.signature')).toBe(false);
	});

	it('returns false when part before tilde is not a 3-segment JWT', () => {
		expect(isSdJwt('notajwt~disclosure')).toBe(false);
	});
});

describe('detectCredentialFormat', () => {
	it('detects MSO_MDOC format', () => {
		const raw = base64url.encode(new Uint8Array([0xa2, 0x6a, 0x00, 0x00]));
		expect(detectCredentialFormat(raw)).toBe(VerifiableCredentialFormat.MSO_MDOC);
	});

	it('detects JWT_VC_JSON format', () => {
		// A plain 3-segment string with no tildes
		const raw = 'eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJ0ZXN0In0.c2lnbmF0dXJl';
		expect(detectCredentialFormat(raw)).toBe(VerifiableCredentialFormat.JWT_VC_JSON);
	});

	it('detects VC_SDJWT format (default SD-JWT variant)', () => {
		// Header: {"alg":"ES256","typ":"vc+sd-jwt"}
		const header = base64url.encode(JSON.stringify({ alg: 'ES256', typ: 'vc+sd-jwt' }));
		const raw = `${header}.payload.signature~disclosure~`;
		expect(detectCredentialFormat(raw)).toBe(VerifiableCredentialFormat.VC_SDJWT);
	});

	it('detects DC_SDJWT format when header typ is dc+sd-jwt', () => {
		const header = base64url.encode(JSON.stringify({ alg: 'ES256', typ: 'dc+sd-jwt' }));
		const raw = `${header}.payload.signature~disclosure~`;
		expect(detectCredentialFormat(raw)).toBe(VerifiableCredentialFormat.DC_SDJWT);
	});

	it('falls back to VC_SDJWT when SD-JWT header cannot be parsed', () => {
		// Invalid base64url header but still matches SD-JWT structure
		const raw = '!!!.payload.signature~disclosure~';
		expect(detectCredentialFormat(raw)).toBe(VerifiableCredentialFormat.VC_SDJWT);
	});

	it('returns null for unrecognized formats', () => {
		expect(detectCredentialFormat('')).toBeNull();
		expect(detectCredentialFormat('just-some-random-text')).toBeNull();
	});
});

describe('isJwtVcJson', () => {
	it('returns true for a 3-segment string without tildes', () => {
		expect(isJwtVcJson('header.payload.signature')).toBe(true);
	});

	it('returns false when tildes are present', () => {
		expect(isJwtVcJson('header.payload.signature~disclosure~')).toBe(false);
	});

	it('returns false when there are not exactly 3 segments', () => {
		expect(isJwtVcJson('only.two')).toBe(false);
		expect(isJwtVcJson('one.two.three.four')).toBe(false);
	});
});

describe('detectSdJwtVariant', () => {
	it('returns DC_SDJWT when header typ is dc+sd-jwt', () => {
		const header = base64url.encode(JSON.stringify({ alg: 'ES256', typ: 'dc+sd-jwt' }));
		const raw = `${header}.payload.signature~disclosure~`;
		expect(detectSdJwtVariant(raw)).toBe(VerifiableCredentialFormat.DC_SDJWT);
	});

	it('returns VC_SDJWT when header typ is vc+sd-jwt', () => {
		const header = base64url.encode(JSON.stringify({ alg: 'ES256', typ: 'vc+sd-jwt' }));
		const raw = `${header}.payload.signature~disclosure~`;
		expect(detectSdJwtVariant(raw)).toBe(VerifiableCredentialFormat.VC_SDJWT);
	});

	it('returns VC_SDJWT when header has no typ', () => {
		const header = base64url.encode(JSON.stringify({ alg: 'ES256' }));
		const raw = `${header}.payload.signature~disclosure~`;
		expect(detectSdJwtVariant(raw)).toBe(VerifiableCredentialFormat.VC_SDJWT);
	});

	it('returns VC_SDJWT when header cannot be decoded', () => {
		expect(detectSdJwtVariant('!!!.payload.signature~disclosure~')).toBe(VerifiableCredentialFormat.VC_SDJWT);
	});
});

describe("detectCredentialFormat with VCDM 2.0", () => {
	it("detects an enveloped VCDM 2.0 credential rather than jwt_vc_json", () => {
		expect(detectCredentialFormat(envelopedVcdm2())).toBe(VerifiableCredentialFormat.VCDM2_JOSE);
	});

	it("detects a Data Integrity credential", () => {
		expect(detectCredentialFormat(JSON.stringify(vcdm2Credential))).toBe(VerifiableCredentialFormat.LDP_VC);
	});

	it("still reports a VCDM 1.1 JWT as jwt_vc_json", () => {
		expect(detectCredentialFormat(vcdm11Jwt())).toBe(VerifiableCredentialFormat.JWT_VC_JSON);
	});
});

describe("detectCredentialFormat", () => {
	it("reports VCDM 2.0-as-SD-JWT rather than SD-JWT VC", () => {
		expect(detectCredentialFormat(unsignedSdJwt(credentialBody)))
			.toBe(VerifiableCredentialFormat.VCDM2_SDJWT);
	});

	it("still reports a credential carrying a vct as SD-JWT VC", () => {
		expect(detectCredentialFormat(unsignedSdJwt({ vct: "https://example/vct" })))
			.toBe(VerifiableCredentialFormat.VC_SDJWT);
	});
});

describe("isMdoc recognises every accepted CBOR prefix", () => {
	const prefixes: Array<[number, number]> = [
		[0xa2, 0x6a], [0xb9, 0x00], [0xa3, 0x67], [0xa3, 0x66], [0xa3, 0x69],
	];

	it.each(prefixes)("accepts a document starting %s %s", (first, second) => {
		const raw = bytesToB64Url(new Uint8Array([first, second, 0x00, 0x00]));
		expect(isMdoc(raw)).toBe(true);
		expect(detectCredentialFormat(raw)).toBe(VerifiableCredentialFormat.MSO_MDOC);
	});

	it("rejects a CBOR prefix it does not recognise", () => {
		expect(isMdoc(bytesToB64Url(new Uint8Array([0xa3, 0x99, 0, 0])))).toBe(false);
	});
});

describe("isMdoc defensive path", () => {
	it("returns false rather than throwing when the input is not a string", () => {
		expect(isMdoc(undefined as unknown as string)).toBe(false);
		expect(isMdoc(null as unknown as string)).toBe(false);
	});
});

describe("isMdoc defensive decoding", () => {
	it("returns false when the input cannot be base64url-decoded at all", () => {
		// A lone surrogate makes the decoder throw rather than return bytes.
		expect(isMdoc("\uD800\uD800")).toBe(false);
	});
});
