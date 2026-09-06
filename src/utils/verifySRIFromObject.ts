export type Algorithm = 'sha256' | 'sha384' | 'sha512';

const algoMap: Record<Algorithm, string> = {
	sha256: 'SHA-256',
	sha384: 'SHA-384',
	sha512: 'SHA-512',
};

/**
 * Verifies a resource against a W3C Subresource Integrity string, as SD-JWT VC
 * Type Metadata uses them for `vct#integrity`, `extends#integrity` and friends.
 *
 * SRI is defined over **the octets of the resource as served**. Pass the raw
 * body whenever it is available.
 *
 * Passing a parsed object is a fallback, and a lossy one: the digest is then
 * taken over `JSON.stringify` of the parse, which reproduces the original bytes
 * only when the document was served compact and its keys survive a round trip
 * in document order. A pretty-printed document — the normal shape of a metadata
 * file served from disk — hashes to something else entirely, and a correct
 * digest is reported as a mismatch. See `verifySRI`'s callers for where the raw
 * body is threaded through.
 *
 * @returns true only when a digest was computed and matched. A malformed or
 * unsupported integrity value returns false rather than throwing: "could not
 * check" is not "checked and passed", and the caller decides what to do about
 * it.
 */
export async function verifySRI(
	subtle: SubtleCrypto,
	content: string | Record<string, any>,
	expectedIntegrity: string,
): Promise<boolean> {
	const raw = typeof content === 'string' ? content : JSON.stringify(content);

	// SRI permits several space-separated digests, strongest first. Any one
	// matching is a match.
	const candidates = expectedIntegrity.trim().split(/\s+/).filter(Boolean);
	if (candidates.length === 0) return false;
	if (candidates.length > 1) {
		for (const candidate of candidates) {
			if (await verifySRI(subtle, raw, candidate)) return true;
		}
		return false;
	}

	const single = candidates[0];
	// Split on the FIRST dash only: base64 in the URL-safe alphabet contains
	// dashes, and splitting on all of them truncates the digest into a
	// guaranteed mismatch.
	const dash = single.indexOf('-');
	if (dash <= 0) return false;

	const algorithm = single.slice(0, dash).toLowerCase() as Algorithm;
	const expectedHash = single.slice(dash + 1);
	const subtleAlgo = algoMap[algorithm];
	if (!subtleAlgo || !expectedHash) return false;

	const expectedBytes = decodeBase64(expectedHash);
	if (!expectedBytes) return false;

	const digest = new Uint8Array(
		await subtle.digest(subtleAlgo, new TextEncoder().encode(raw)),
	);

	// Compared as bytes, not as base64 text, so the standard and URL-safe
	// spellings of the same digest are not reported as different.
	if (digest.length !== expectedBytes.length) return false;
	let difference = 0;
	for (let i = 0; i < digest.length; i++) {
		difference |= digest[i] ^ expectedBytes[i];
	}
	return difference === 0;
}

/**
 * @deprecated Prefer {@link verifySRI} with the raw response body. Hashing a
 * parsed object cannot reproduce the served bytes in general - see verifySRI.
 */
export async function verifySRIFromObject(
	subtle: SubtleCrypto,
	obj: Record<string, any>,
	expectedIntegrity: string,
): Promise<boolean> {
	return verifySRI(subtle, obj, expectedIntegrity);
}

function decodeBase64(value: string): Uint8Array | null {
	const normalised = value.replace(/-/g, '+').replace(/_/g, '/');
	const padded = normalised + '='.repeat((4 - (normalised.length % 4)) % 4);
	try {
		const binary = atob(padded);
		const out = new Uint8Array(binary.length);
		for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
		return out;
	} catch {
		return null;
	}
}
