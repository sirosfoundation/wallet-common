import { describe, expect, it } from "vitest";
import {
	toTypeArray, primaryCredentialType, issuerIdentifier, issuerDisplayName,
	extractVcdm2ValidityInfo, isVcdm2Credential, decodeEnvelopedVcdm2,
	splitSdJwt, decodeVcdm2SdJwt, proofsOf, coerceCredentialObject,
	isVcdm2JoseHeaderType, decodeCompactJws,
	validatedIssuerIdentifier, validatedIssuerDisplayName,
} from "./vcdm2";
import { b64url as enc, unsignedSdJwt, VCDM2_CONTEXT } from "../testFixtures/vcdm2TestSupport";

const ISSUER = "did:example:issuer";

const genericCredential = {
	"@context": [VCDM2_CONTEXT],
	type: ["VerifiableCredential"],
	issuer: ISSUER,
	credentialSubject: { id: "did:example:subject" },
};

const credentialBody = {
	"@context": [VCDM2_CONTEXT],
	type: ["VerifiableCredential", "StudentCardCredential"],
	issuer: ISSUER,
	credentialSubject: { id: "did:example:subject", given_name: "Alice" },
};


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

describe("isVcdm2Credential structural guards", () => {
	it("rejects an array", () => {
		expect(isVcdm2Credential([])).toBe(false);
	});

	it("rejects null and primitives", () => {
		expect(isVcdm2Credential(null)).toBe(false);
		expect(isVcdm2Credential("string")).toBe(false);
	});

	it("rejects a credential with no type", () => {
		expect(isVcdm2Credential({
			"@context": ["https://www.w3.org/ns/credentials/v2"],
			issuer: "did:example:issuer",
		})).toBe(false);
	});

	it("rejects a credential with no issuer", () => {
		expect(isVcdm2Credential({
			"@context": ["https://www.w3.org/ns/credentials/v2"],
			type: ["VerifiableCredential"],
		})).toBe(false);
	});

	it("rejects an empty or non-array @context", () => {
		expect(isVcdm2Credential({ "@context": [], type: [], issuer: "x" })).toBe(false);
		expect(isVcdm2Credential({ "@context": "v2", type: [], issuer: "x" })).toBe(false);
	});
});

describe("decodeEnvelopedVcdm2", () => {
	it("declines a JWS with no typ whose payload is not a VCDM 2.0 credential", () => {
		expect(decodeEnvelopedVcdm2(`${enc({ alg: "ES256" })}.${enc({ sub: "x" })}.sig`)).toBeNull();
	});

	it("accepts a JWS with no typ whose payload is itself a VCDM 2.0 credential", () => {
		const decoded = decodeEnvelopedVcdm2(`${enc({ alg: "ES256" })}.${enc(genericCredential)}.sig`);
		expect(decoded).not.toBeNull();
		expect(decoded?.payload.issuer).toBe("did:example:issuer");
	});

	it("declines a JWS whose payload wraps a VCDM 1.1 credential", () => {
		expect(decodeEnvelopedVcdm2(`${enc({ alg: "ES256" })}.${enc({ vc: { type: ["X"] } })}.sig`)).toBeNull();
	});
});

describe("splitSdJwt", () => {
	it("splits an SD-JWT with no disclosures", () => {
		const split = splitSdJwt("a.b.c~");
		expect(split).toEqual({ issuerJwt: "a.b.c", rest: [] });
	});

	it("returns the disclosures when present", () => {
		expect(splitSdJwt("a.b.c~d1~d2~")?.rest).toEqual(["d1", "d2"]);
	});

	it("declines a plain JWT with no tilde", () => {
		expect(splitSdJwt("a.b.c")).toBeNull();
	});

	it("declines a non-string and a malformed issuer JWT", () => {
		expect(splitSdJwt(42)).toBeNull();
		expect(splitSdJwt("not-a-jwt~")).toBeNull();
	});
});

describe("decodeVcdm2SdJwt", () => {
	it("accepts a VCDM 2.0 credential in an SD-JWT", () => {
		expect(decodeVcdm2SdJwt(unsignedSdJwt(credentialBody))).not.toBeNull();
	});

	it("leaves a real SD-JWT VC alone, because it carries a vct", () => {
		expect(decodeVcdm2SdJwt(unsignedSdJwt({ vct: "https://example/vct", iss: ISSUER }))).toBeNull();
	});

	it("declines an SD-JWT whose payload is not a VCDM 2.0 credential", () => {
		expect(decodeVcdm2SdJwt(unsignedSdJwt({ hello: "world" }))).toBeNull();
	});

	it("declines a plain JWT and undecodable input", () => {
		expect(decodeVcdm2SdJwt(`${enc({ alg: "ES256" })}.${enc(credentialBody)}.sig`)).toBeNull();
		expect(decodeVcdm2SdJwt("%%%.%%%.sig~")).toBeNull();
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
