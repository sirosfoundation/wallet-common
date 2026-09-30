import { describe, expect, it } from "vitest";
import { base58Decode, multibaseDecode, multikeyToJwk, didKeyToJwk } from "./multibase";
import { subtle, bytesToB64Url, b64ToBytes, b64UrlToBytes as base64UrlDecode } from "../../testFixtures/vcdm2TestSupport";

const base64UrlEncode = bytesToB64Url;

describe("base58Decode", () => {
	it("decodes the Bitcoin base58 test vectors", () => {
		expect(Array.from(base58Decode("2NEpo7TZRRrLZSi2U"))).toEqual(
			Array.from(new TextEncoder().encode("Hello World!")),
		);
		expect(base58Decode("").length).toBe(0);
	});

	it("decodes leading '1' characters as leading zero bytes", () => {
		expect(Array.from(base58Decode("1112"))).toEqual([0, 0, 0, 1]);
	});

	it("rejects characters outside the alphabet", () => {
		// '0', 'O', 'I' and 'l' are excluded from the base58btc alphabet.
		expect(() => base58Decode("0OIl")).toThrow();
	});
});

describe("multibaseDecode", () => {
	it("supports base58btc ('z') and base64url ('u')", () => {
		const bytes = new Uint8Array([1, 2, 3, 250]);
		expect(Array.from(multibaseDecode("u" + base64UrlEncode(bytes)))).toEqual([1, 2, 3, 250]);
		expect(Array.from(multibaseDecode("z2NEpo7TZRRrLZSi2U"))).toEqual(
			Array.from(new TextEncoder().encode("Hello World!")),
		);
	});

	it("rejects an unsupported multibase prefix", () => {
		expect(() => multibaseDecode("f00ff")).toThrow(/unsupported prefix/);
	});
});

describe("multikeyToJwk", () => {
	it("decodes an Ed25519 multikey", () => {
		const raw = new Uint8Array(32).fill(7);
		const multikey = new Uint8Array([0xed, 0x01, ...raw]);
		const jwk = multikeyToJwk(multikey);
		expect(jwk.kty).toBe("OKP");
		expect(jwk.crv).toBe("Ed25519");
		expect(base64UrlDecode(jwk.x as string)).toEqual(raw);
	});

	it("recovers x and y from a compressed P-256 point", async () => {
		// Generating a real key is the only honest way to test point
		// decompression — a hand-written vector would just encode my own
		// arithmetic back at me.
		const keyPair = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
		const jwk = await subtle.exportKey("jwk", keyPair.publicKey);

		const x = base64UrlDecode(jwk.x as string);
		const y = base64UrlDecode(jwk.y as string);
		const compressed = new Uint8Array([(y[y.length - 1] & 1) === 1 ? 0x03 : 0x02, ...x]);
		const multikey = new Uint8Array([0x80, 0x24, ...compressed]);

		const decoded = multikeyToJwk(multikey);
		expect(decoded.kty).toBe("EC");
		expect(decoded.crv).toBe("P-256");
		expect(decoded.x).toBe(jwk.x);
		expect(decoded.y).toBe(jwk.y);
	});

	it("accepts an uncompressed point as well", async () => {
		const keyPair = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
		const jwk = await subtle.exportKey("jwk", keyPair.publicKey);
		const x = base64UrlDecode(jwk.x as string);
		const y = base64UrlDecode(jwk.y as string);
		const multikey = new Uint8Array([0x80, 0x24, 0x04, ...x, ...y]);

		const decoded = multikeyToJwk(multikey);
		expect(decoded.x).toBe(jwk.x);
		expect(decoded.y).toBe(jwk.y);
	});

	it("rejects an unknown multicodec prefix", () => {
		expect(() => multikeyToJwk(new Uint8Array([0x99, 0x99, 1, 2, 3]))).toThrow(/unsupported key type/);
	});
});

describe("didKeyToJwk", () => {
	it("resolves a did:key identifier, ignoring any fragment", () => {
		const raw = new Uint8Array(32).fill(3);
		const multikey = new Uint8Array([0xed, 0x01, ...raw]);
		const did = `did:key:u${base64UrlEncode(multikey)}`;

		const withoutFragment = didKeyToJwk(did);
		const withFragment = didKeyToJwk(`${did}#key-1`);
		expect(withoutFragment).toEqual(withFragment);
		expect(withoutFragment.crv).toBe("Ed25519");
	});
});

describe("point decompression covers both y parities", () => {
	it("recovers x and y whichever parity the point has", async () => {
		const seen = new Set<number>();

		// Parity depends on the generated key, so generate until both the
		// even and odd cases have been exercised.
		for (let attempt = 0; attempt < 40 && seen.size < 2; attempt += 1) {
			const keyPair = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
			const jwk = await subtle.exportKey("jwk", keyPair.publicKey);
			const dec = (v: string) => {
				const padded = v + "=".repeat((4 - (v.length % 4)) % 4);
				return Uint8Array.from(atob(padded.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
			};
			const x = dec(jwk.x as string);
			const y = dec(jwk.y as string);
			const parity = y[y.length - 1] & 1;
			seen.add(parity);

			const compressed = new Uint8Array([parity === 1 ? 0x03 : 0x02, ...x]);
			const decoded = multikeyToJwk(new Uint8Array([0x80, 0x24, ...compressed]));
			expect(decoded.x).toBe(jwk.x);
			expect(decoded.y).toBe(jwk.y);
		}

		expect(seen.size).toBe(2);
	});
});

describe("multikeyToJwk length guard", () => {
	it("rejects a multikey shorter than its own prefix", () => {
		expect(() => multikeyToJwk(new Uint8Array([0xed]))).toThrow(/unsupported key type/);
	});
});

describe("multibase and multikey edge cases", () => {
	it("rejects a value that is too short to carry a prefix", () => {
		expect(() => multibaseDecode("z")).toThrow(/too short/);
		expect(() => multibaseDecode(42 as unknown as string)).toThrow(/too short/);
	});

	it("rejects a multikey whose EC point is neither compressed nor uncompressed", () => {
		// 0x80 0x24 is the P-256 prefix; 0x05 is not a valid point marker.
		expect(() => multikeyToJwk(new Uint8Array([0x80, 0x24, 0x05, 1, 2, 3])))
			.toThrow(/not a compressed EC point/);
	});

	it("decompresses a P-384 point", async () => {
		const keyPair = await globalThis.crypto.subtle.generateKey(
			{ name: "ECDSA", namedCurve: "P-384" }, true, ["sign", "verify"],
		);
		const jwk = await globalThis.crypto.subtle.exportKey("jwk", keyPair.publicKey);

		const dec = (v: string) => {
			const padded = v + "=".repeat((4 - (v.length % 4)) % 4);
			const binary = atob(padded.replace(/-/g, "+").replace(/_/g, "/"));
			return Uint8Array.from(binary, (c) => c.charCodeAt(0));
		};
		const x = dec(jwk.x as string);
		const y = dec(jwk.y as string);
		const compressed = new Uint8Array([(y[y.length - 1] & 1) === 1 ? 0x03 : 0x02, ...x]);

		const decoded = multikeyToJwk(new Uint8Array([0x81, 0x24, ...compressed]));
		expect(decoded.crv).toBe("P-384");
		expect(decoded.x).toBe(jwk.x);
		expect(decoded.y).toBe(jwk.y);
	});

	it("rejects a did:key identifier that is not did:key", () => {
		expect(() => didKeyToJwk("did:example:123")).toThrow(/unexpected identifier/);
	});
});
