import { base64url } from 'jose';
import { VerifiableCredentialFormat } from '../types';

/**
 * Detects the format of a verifiable credential based on its raw string representation.
 */
export function detectCredentialFormat(raw: string): VerifiableCredentialFormat | null {
	if (isMdoc(raw)) return VerifiableCredentialFormat.MSO_MDOC;
	if (isJwtVcJson(raw)) return VerifiableCredentialFormat.JWT_VC_JSON;
	if (isSdJwt(raw)) return detectSdJwtVariant(raw);
	return null;
}

/**
 * Detect if a credential is an mdoc by checking the CBOR magic bytes
 * after base64url-decoding the first few characters.
 */
export function isMdoc(raw: string): boolean {
	try {
		const bytes = base64url.decode(raw.slice(0, 4));
		return (
			(bytes[0] === 0xA2 && bytes[1] === 0x6A) ||
			(bytes[0] === 0xB9 && bytes[1] === 0x00) ||
			(bytes[0] === 0xA3 && bytes[1] === 0x67) ||
			(bytes[0] === 0xA3 && bytes[1] === 0x66) ||
			(bytes[0] === 0xA3 && bytes[1] === 0x69)
		);
	} catch {
		return false;
	}
}

/**
 * Detect if a credential is an SD-JWT by checking for the presence
 * of tilde-separated disclosures and a valid JWT structure.
 */
export function isSdJwt(raw: string): boolean {
	const tildeIdx = raw.indexOf('~');
	if (tildeIdx === -1) return false;
	return raw.slice(0, tildeIdx).split('.').length === 3;
}

/**
 * Detect if a credential is a JWT VC in JSON format by checking for the absence
 * of tilde-separated disclosures and the presence of three dot-separated segments.
 */
export function isJwtVcJson(raw: string): boolean {
	if (raw.includes('~')) return false;
	return raw.split('.').length === 3;
}

/**
 * Distinguish between the SD-JWT-based formats.
 *
 * A "dc+sd-jwt" typ is an SD-JWT VC. Otherwise the payload decides: VC-JOSE-COSE §3.2.1 secures a
 * W3C VCDM 2.0 credential with the same "vc+sd-jwt" typ as the legacy SD-JWT VC format, and the
 * two are told apart by their claims — a `vct` means SD-JWT VC, a JSON-LD `@context` without a
 * `vct` means VCDM 2.0.
 */
export function detectSdJwtVariant(raw: string): VerifiableCredentialFormat {
	try {
		const firstDot = raw.indexOf('.');
		const rawHeader = raw.slice(0, firstDot);
		const headerBuff = base64url.decode(rawHeader);
		const decodedHeader = new TextDecoder().decode(headerBuff);
		const header = JSON.parse(decodedHeader);
		if (header.typ === 'dc+sd-jwt') return VerifiableCredentialFormat.DC_SDJWT;
	} catch {}

	if (isW3CVcdmSdJwtPayload(raw)) return VerifiableCredentialFormat.W3C_VCDM_SDJWT;
	return VerifiableCredentialFormat.VC_SDJWT;
}

/**
 * Inspect an SD-JWT's payload for the W3C VCDM 2.0 shape: a JSON-LD `@context` and no `vct`.
 */
export function isW3CVcdmSdJwtPayload(raw: string): boolean {
	try {
		const [, rawPayload] = raw.split('~')[0].split('.');
		const payload = JSON.parse(new TextDecoder().decode(base64url.decode(rawPayload)));
		return payload['@context'] !== undefined && payload.vct === undefined;
	} catch {
		return false;
	}
}
