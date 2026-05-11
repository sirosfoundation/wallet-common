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
			(bytes[0] === 0xB9 && bytes[1] === 0x00)
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
function isJwtVcJson(raw: string): boolean {
	if (raw.includes('~')) return false;
	return raw.split('.').length === 3;
}

/**
 * For SD-JWTs, we need to distinguish between "vc+sd-jwt" and "dc+sd-jwt" variants.
 */
function detectSdJwtVariant(raw: string): VerifiableCredentialFormat {
	try {
		const firstDot = raw.indexOf('.');
		const rawHeader = raw.slice(0, firstDot);
		const headerBuff = base64url.decode(rawHeader);
		const decodedHeader = new TextDecoder().decode(headerBuff);
		const header = JSON.parse(decodedHeader);
		if (header.typ === 'dc+sd-jwt') return VerifiableCredentialFormat.DC_SDJWT;
	} catch {}
	return VerifiableCredentialFormat.VC_SDJWT;
}
