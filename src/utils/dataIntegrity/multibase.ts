import type { JWK } from "jose";

/**
 * Multibase / Multikey decoding, as used by Data Integrity `proofValue`s and
 * by `did:key` verification methods.
 *
 * Only the encodings the relevant cryptosuites actually produce are handled:
 * base58btc (`z`) and base64url-no-pad (`u`).
 */

const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

const BASE58_LOOKUP: Record<string, number> = (() => {
	const table: Record<string, number> = {};
	for (let i = 0; i < BASE58_ALPHABET.length; i += 1) {
		table[BASE58_ALPHABET[i]] = i;
	}
	return table;
})();

/** Decode a base58btc string to bytes. Throws on an invalid character. */
export function base58Decode(input: string): Uint8Array {
	if (input.length === 0) return new Uint8Array(0);

	const bytes: number[] = [0];
	for (const char of input) {
		const value = BASE58_LOOKUP[char];
		if (value === undefined) {
			throw new Error(`base58: invalid character '${char}'`);
		}

		let carry = value;
		for (let j = 0; j < bytes.length; j += 1) {
			carry += bytes[j] * 58;
			bytes[j] = carry & 0xff;
			carry >>= 8;
		}
		while (carry > 0) {
			bytes.push(carry & 0xff);
			carry >>= 8;
		}
	}

	// Each leading '1' encodes a leading zero byte.
	for (let k = 0; k < input.length && input[k] === "1"; k += 1) {
		bytes.push(0);
	}

	return new Uint8Array(bytes.reverse());
}

function base64UrlDecode(input: string): Uint8Array {
	const padded = input + "=".repeat((4 - (input.length % 4)) % 4);
	const binary = atob(padded.replace(/-/g, "+").replace(/_/g, "/"));
	const out = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i);
	return out;
}

/** Decode a multibase string. Supports base58btc ('z') and base64url ('u'). */
export function multibaseDecode(input: string): Uint8Array {
	if (typeof input !== "string" || input.length < 2) {
		throw new Error("multibase: value is too short");
	}
	const prefix = input[0];
	const body = input.slice(1);

	if (prefix === "z") return base58Decode(body);
	if (prefix === "u") return base64UrlDecode(body);

	throw new Error(`multibase: unsupported prefix '${prefix}'`);
}

function base64UrlEncode(bytes: Uint8Array): string {
	let binary = "";
	for (const byte of bytes) binary += String.fromCharCode(byte);
	return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * Multicodec key prefixes (varint-encoded) for the key types the supported
 * cryptosuites use.
 */
const MULTICODEC = {
	ED25519_PUB: [0xed, 0x01],
	P256_PUB: [0x80, 0x24],
	P384_PUB: [0x81, 0x24],
} as const;

function hasPrefix(bytes: Uint8Array, prefix: readonly number[]): boolean {
	if (bytes.length < prefix.length) return false;
	return prefix.every((b, i) => bytes[i] === b);
}

/**
 * Decompress a SEC1 compressed P-256/P-384 point to its affine coordinates.
 *
 * Recovers y from x via y² = x³ - 3x + b over the curve's prime field, using
 * the fact that p ≡ 3 (mod 4) for both curves, so the square root is
 * y = (y²)^((p+1)/4).
 */
function decompressPoint(compressed: Uint8Array, curve: "P-256" | "P-384"): { x: Uint8Array; y: Uint8Array } {
	const params = curve === "P-256"
		? {
			p: BigInt("0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff"),
			b: BigInt("0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b"),
			size: 32,
		}
		: {
			p: BigInt("0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff"),
			b: BigInt("0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef"),
			size: 48,
		};

	const sign = compressed[0];
	if (sign !== 0x02 && sign !== 0x03) {
		throw new Error("multikey: not a compressed EC point");
	}

	const toBigInt = (bytes: Uint8Array): bigint => {
		let value = 0n;
		for (const byte of bytes) value = (value << 8n) | BigInt(byte);
		return value;
	};

	const toBytes = (value: bigint, size: number): Uint8Array => {
		const out = new Uint8Array(size);
		let v = value;
		for (let i = size - 1; i >= 0; i -= 1) {
			out[i] = Number(v & 0xffn);
			v >>= 8n;
		}
		return out;
	};

	const modPow = (base: bigint, exponent: bigint, modulus: bigint): bigint => {
		let result = 1n;
		let b = base % modulus;
		let e = exponent;
		while (e > 0n) {
			if (e & 1n) result = (result * b) % modulus;
			b = (b * b) % modulus;
			e >>= 1n;
		}
		return result;
	};

	const x = toBigInt(compressed.slice(1));
	const { p, b, size } = params;

	const ySquared = (modPow(x, 3n, p) - 3n * x + b) % p;
	const normalized = ((ySquared % p) + p) % p;
	let y = modPow(normalized, (p + 1n) / 4n, p);

	// Pick the root whose parity matches the sign byte.
	const wantOdd = sign === 0x03;
	if ((y & 1n) === 1n !== wantOdd) {
		y = p - y;
	}

	return { x: toBytes(x, size), y: toBytes(y, size) };
}

/**
 * Convert a Multikey (multicodec-prefixed public key bytes) to a JWK.
 */
export function multikeyToJwk(bytes: Uint8Array): JWK {
	if (hasPrefix(bytes, MULTICODEC.ED25519_PUB)) {
		return {
			kty: "OKP",
			crv: "Ed25519",
			x: base64UrlEncode(bytes.slice(MULTICODEC.ED25519_PUB.length)),
		};
	}

	for (const [curve, prefix] of [["P-256", MULTICODEC.P256_PUB], ["P-384", MULTICODEC.P384_PUB]] as const) {
		if (!hasPrefix(bytes, prefix)) continue;

		const keyBytes = bytes.slice(prefix.length);
		// Compressed form (0x02/0x03 || x) is what Multikey mandates, but
		// tolerate the uncompressed form (0x04 || x || y) too.
		if (keyBytes[0] === 0x04) {
			const size = (keyBytes.length - 1) / 2;
			return {
				kty: "EC",
				crv: curve,
				x: base64UrlEncode(keyBytes.slice(1, 1 + size)),
				y: base64UrlEncode(keyBytes.slice(1 + size)),
			};
		}

		const { x, y } = decompressPoint(keyBytes, curve);
		return {
			kty: "EC",
			crv: curve,
			x: base64UrlEncode(x),
			y: base64UrlEncode(y),
		};
	}

	throw new Error("multikey: unsupported key type");
}

/**
 * Resolve a `did:key:z...` identifier to its JWK. The method-specific
 * identifier is a multibase-encoded Multikey.
 */
export function didKeyToJwk(did: string): JWK {
	const withoutFragment = did.split("#")[0];
	const prefix = "did:key:";
	if (!withoutFragment.startsWith(prefix)) {
		throw new Error("did:key: unexpected identifier");
	}
	return multikeyToJwk(multibaseDecode(withoutFragment.slice(prefix.length)));
}
