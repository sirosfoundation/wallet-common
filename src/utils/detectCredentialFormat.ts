import { base64url } from 'jose';
import { VerifiableCredentialFormat } from '../types';
import { coerceCredentialObject, isVcdm2Credential, looksLikeEnvelopedVcdm2 } from './vcdm2';

/**
 * Detects the format of a verifiable credential based on its raw string representation.
 *
 * Order matters. `isJwtVcJson` is a purely structural check that matches any
 * three-segment token, so the more specific VCDM 2.0 checks have to run first
 * or an enveloped VCDM 2.0 credential would be misreported as VCDM 1.1
 * `jwt_vc_json` — and then rejected downstream for lacking a `vc` claim.
 */
export function detectCredentialFormat(raw: string): VerifiableCredentialFormat | null {
	if (isMdoc(raw)) return VerifiableCredentialFormat.MSO_MDOC;
	if (isLdpVc(raw)) return VerifiableCredentialFormat.LDP_VC;
	if (isSdJwt(raw)) return detectSdJwtVariant(raw);
	if (looksLikeEnvelopedVcdm2(raw)) return VerifiableCredentialFormat.VCDM2_JOSE;
	if (isJwtVcJson(raw)) return VerifiableCredentialFormat.JWT_VC_JSON;
	return null;
}

/**
 * Detect a W3C VCDM 2.0 credential secured with an embedded Data Integrity
 * proof. Unlike every other supported format this is a JSON-LD object rather
 * than a compact token, so it arrives as JSON text.
 */
export function isLdpVc(raw: string): boolean {
	const candidate = coerceCredentialObject(raw);
	return candidate !== null && isVcdm2Credential(candidate);
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
 * Distinguish between VC-SD-JWT and DC-SD-JWT by inspecting the JWT header's "typ" field.
 * If the "typ" is "dc+sd-jwt", it's a DC-SD-JWT; otherwise, it's a VC-SD-JWT.
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
	return VerifiableCredentialFormat.VC_SDJWT;
}
