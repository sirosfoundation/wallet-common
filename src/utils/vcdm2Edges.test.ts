import { describe, expect, it, vi } from "vitest";
import {
	coerceCredentialObject,
	decodeCompactJws,
	extractVcdm2ValidityInfo,
	issuerDisplayName,
	issuerIdentifier,
	isVcdm2JoseHeaderType,
	primaryCredentialType,
	validatedIssuerDisplayName,
	validatedIssuerIdentifier,
	proofsOf,
	toTypeArray,
} from "./vcdm2";
import { canonicalizeJcs } from "./dataIntegrity/jcs";
import { didKeyToJwk, multibaseDecode, multikeyToJwk } from "./dataIntegrity/multibase";
import { isMdoc } from "./detectCredentialFormat";
import { ParsingEngine } from "../ParsingEngine";
import { CredentialParsingError } from "../error";
import type { CredentialParser } from "../interfaces";

/**
 * Branch coverage for the smaller VCDM 2.0 helpers — the paths that only a
 * malformed or unusual credential reaches.
 */

describe("toTypeArray", () => {
	it("wraps a bare string", () => {
		expect(toTypeArray("VerifiableCredential")).toEqual(["VerifiableCredential"]);
	});

	it("keeps only the string entries of an array", () => {
		expect(toTypeArray(["A", 1, null, "B"])).toEqual(["A", "B"]);
	});

	it("returns an empty array for anything else", () => {
		expect(toTypeArray(undefined)).toEqual([]);
		expect(toTypeArray(42)).toEqual([]);
		expect(toTypeArray({})).toEqual([]);
	});
});

describe("primaryCredentialType", () => {
	it("skips the generic VerifiableCredential entry", () => {
		expect(primaryCredentialType(["VerifiableCredential", "DiplomaCredential"])).toBe("DiplomaCredential");
	});

	it("returns undefined when only the generic type is present", () => {
		expect(primaryCredentialType(["VerifiableCredential"])).toBeUndefined();
	});
});

describe("issuerIdentifier", () => {
	it("accepts a string issuer", () => {
		expect(issuerIdentifier("did:example:issuer")).toBe("did:example:issuer");
	});

	it("accepts an object issuer with an id", () => {
		expect(issuerIdentifier({ id: "did:example:issuer" })).toBe("did:example:issuer");
	});

	it("returns undefined when there is no usable identifier", () => {
		expect(issuerIdentifier({ name: "no id" })).toBeUndefined();
		expect(issuerIdentifier(undefined)).toBeUndefined();
		expect(issuerIdentifier(42)).toBeUndefined();
	});
});

describe("issuerDisplayName", () => {
	it("prefers a plain string name", () => {
		expect(issuerDisplayName({ id: "did:example:x", name: "Example Uni" })).toBe("Example Uni");
	});

	it("reads a JSON-LD language array using @value", () => {
		expect(issuerDisplayName({ id: "did:x", name: [{ "@value": "Universitet", "@language": "sv" }] }))
			.toBe("Universitet");
	});

	it("reads a language array using a plain value member", () => {
		expect(issuerDisplayName({ id: "did:x", name: [{ value: "Universiteit" }] })).toBe("Universiteit");
	});

	it("falls back to the identifier when the name array has nothing usable", () => {
		expect(issuerDisplayName({ id: "did:example:x", name: [{ other: 1 }] })).toBe("did:example:x");
	});

	it("falls back to the identifier when there is no name", () => {
		expect(issuerDisplayName({ id: "did:example:x" })).toBe("did:example:x");
		expect(issuerDisplayName("did:example:x")).toBe("did:example:x");
	});
});

describe("extractVcdm2ValidityInfo", () => {
	const base = {
		"@context": ["https://www.w3.org/ns/credentials/v2"],
		type: ["VerifiableCredential"],
		issuer: "did:example:issuer",
		credentialSubject: {},
	} as any;

	it("ignores unparseable date strings", () => {
		const info = extractVcdm2ValidityInfo({ ...base, validFrom: "not-a-date", validUntil: "also-bad" });
		expect(info.validFrom).toBeUndefined();
		expect(info.validUntil).toBeUndefined();
	});

	it("ignores non-string date members", () => {
		const info = extractVcdm2ValidityInfo({ ...base, validFrom: 12345 } as any);
		expect(info.validFrom).toBeUndefined();
	});

	it("lets JWT claims override the credential's own dates", () => {
		const info = extractVcdm2ValidityInfo(
			{ ...base, validFrom: "2020-01-01T00:00:00Z", validUntil: "2021-01-01T00:00:00Z" },
			{ nbf: 1700000000, exp: 1800000000, iat: 1650000000 },
		);
		expect(info.validFrom).toEqual(new Date(1700000000 * 1000));
		expect(info.validUntil).toEqual(new Date(1800000000 * 1000));
		expect(info.signed).toEqual(new Date(1650000000 * 1000));
	});
});

describe("proofsOf", () => {
	const base = { "@context": [], type: [], issuer: "x", credentialSubject: {} } as any;

	it("returns an empty array when there is no proof", () => {
		expect(proofsOf(base)).toEqual([]);
	});

	it("wraps a single proof", () => {
		expect(proofsOf({ ...base, proof: { type: "A" } })).toHaveLength(1);
	});

	it("passes an array of proofs through", () => {
		expect(proofsOf({ ...base, proof: [{ type: "A" }, { type: "B" }] })).toHaveLength(2);
	});
});

describe("coerceCredentialObject", () => {
	it("returns an object unchanged", () => {
		const value = { a: 1 };
		expect(coerceCredentialObject(value)).toBe(value);
	});

	it("parses JSON text", () => {
		expect(coerceCredentialObject('{"a":1}')).toEqual({ a: 1 });
	});

	it("returns null for malformed JSON", () => {
		expect(coerceCredentialObject("{not json")).toBeNull();
	});

	it("returns null for text that is not an object", () => {
		expect(coerceCredentialObject("[1,2]")).toBeNull();
		expect(coerceCredentialObject("plain")).toBeNull();
	});

	it("returns null for non-object, non-string input", () => {
		expect(coerceCredentialObject(42)).toBeNull();
		expect(coerceCredentialObject(null)).toBeNull();
		expect(coerceCredentialObject([1])).toBeNull();
	});
});

describe("isVcdm2JoseHeaderType", () => {
	it("accepts the known typ values case-insensitively", () => {
		expect(isVcdm2JoseHeaderType("vc+jwt")).toBe(true);
		expect(isVcdm2JoseHeaderType("VC-LD+JWT")).toBe(true);
	});

	it("rejects anything else", () => {
		expect(isVcdm2JoseHeaderType("dc+sd-jwt")).toBe(false);
		expect(isVcdm2JoseHeaderType(undefined)).toBe(false);
		expect(isVcdm2JoseHeaderType(7)).toBe(false);
	});
});

describe("decodeCompactJws", () => {
	it("returns null for a non-string", () => {
		expect(decodeCompactJws(42)).toBeNull();
	});

	it("returns null for an SD-JWT", () => {
		expect(decodeCompactJws("a.b.c~d~")).toBeNull();
	});

	it("returns null when there are not three segments", () => {
		expect(decodeCompactJws("a.b")).toBeNull();
	});

	it("returns null when a segment is not valid base64url JSON", () => {
		expect(decodeCompactJws("%%%.%%%.sig")).toBeNull();
	});
});

describe("canonicalizeJcs rejects non-JSON types", () => {
	it("throws for a bigint", () => {
		expect(() => canonicalizeJcs({ a: 1n })).toThrow(/not serializable/);
	});

	it("throws for a function", () => {
		expect(() => canonicalizeJcs({ a: () => 1 })).toThrow(/not serializable/);
	});

	it("throws for a symbol", () => {
		expect(() => canonicalizeJcs(Symbol("s"))).toThrow(/not serializable/);
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

describe("isMdoc", () => {
	it("returns false when the input cannot be base64url-decoded at all", () => {
		// A lone surrogate makes the decoder throw rather than return bytes.
		expect(isMdoc("\uD800\uD800")).toBe(false);
	});
});

describe("ParsingEngine dispatch", () => {
	it("moves past a parser that declines the format", async () => {
		const declining: CredentialParser = {
			parse: vi.fn(async () => ({ success: false as const, error: CredentialParsingError.UnsupportedFormat })),
		};
		const accepting: CredentialParser = {
			parse: vi.fn(async () => ({ success: true as const, value: { marker: "handled" } as any })),
		};

		const engine = ParsingEngine();
		engine.register(declining);
		engine.register(accepting);

		const result = await engine.parse({ rawCredential: "anything" });
		expect(result.success).toBe(true);
		expect(declining.parse).toHaveBeenCalled();
		expect(accepting.parse).toHaveBeenCalled();
	});

	it("returns a non-UnsupportedFormat failure immediately", async () => {
		const failing: CredentialParser = {
			parse: vi.fn(async () => ({ success: false as const, error: CredentialParsingError.CouldNotParse })),
		};
		const later: CredentialParser = { parse: vi.fn() };

		const engine = ParsingEngine();
		engine.register(failing);
		engine.register(later);

		const result = await engine.parse({ rawCredential: "anything" });
		expect(result.success).toBe(false);
		if (!result.success) expect(result.error).toBe(CredentialParsingError.CouldNotParse);
		expect(later.parse).not.toHaveBeenCalled();
	});

	it("reports UnsupportedFormat when every parser declines", async () => {
		const declining: CredentialParser = {
			parse: async () => ({ success: false as const, error: CredentialParsingError.UnsupportedFormat }),
		};

		const engine = ParsingEngine();
		engine.register(declining);

		const result = await engine.parse({ rawCredential: "anything" });
		expect(result.success).toBe(false);
		if (!result.success) expect(result.error).toBe(CredentialParsingError.UnsupportedFormat);
	});
});

describe("validated issuer helpers", () => {
	it("reads a string issuer", () => {
		expect(validatedIssuerIdentifier("did:example:issuer")).toBe("did:example:issuer");
		expect(validatedIssuerDisplayName("did:example:issuer")).toBe("did:example:issuer");
	});

	it("reads an object issuer", () => {
		expect(validatedIssuerIdentifier({ id: "did:example:issuer" })).toBe("did:example:issuer");
		expect(validatedIssuerDisplayName({ id: "did:example:issuer", name: "Example" })).toBe("Example");
	});

	it("falls back to the identifier when the object has no usable name", () => {
		expect(validatedIssuerDisplayName({ id: "did:example:issuer" })).toBe("did:example:issuer");
	});
});
