import { base64url } from 'jose';
import { describe, expect, it } from 'vitest';
import { VerifiableCredentialFormat } from '../types';
import { detectCredentialFormat, detectSdJwtVariant, isMdoc, isJwtVcJson, isSdJwt } from './detectCredentialFormat';

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
