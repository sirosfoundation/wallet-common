import { describe, expect, it, vi } from "vitest";
import { JWK } from "jose";
import {
	DidPublicKeyResolver,
	createDidResolver,
	didWebToUrl,
	findPublicKeyInDidDocument,
	resolveDidJwk,
	resolveDidWeb,
} from "./didResolver";
import { DIDDocument } from "../protocols/openid4vp/types";
import { toBase64Url } from "../utils/util";

const P256_JWK: JWK = {
	kty: "EC",
	crv: "P-256",
	x: "acbIQiuMs3i8_uszEjJ2tpTtRM4EU3yz91PH6CdH2V0",
	y: "_KcyLj9vWMptnmKtm46GqDz8wf74I5LKgrl2GzH3nSE",
};

const toDidJwk = (jwk: JWK) => `did:jwk:${toBase64Url(new TextEncoder().encode(JSON.stringify(jwk)))}`;

describe("resolveDidJwk", () => {
	it("resolves a did:jwk into a document with #0 in both DIIP relationships", () => {
		const did = toDidJwk(P256_JWK);
		const result = resolveDidJwk(did);

		expect(result.resolved).toBe(true);
		expect(result.didDocument?.id).toBe(did);
		expect(result.didDocument?.verificationMethod?.[0].id).toBe(`${did}#0`);
		expect(result.didDocument?.verificationMethod?.[0].publicKeyJwk).toEqual(P256_JWK);
		// DIIP uses assertionMethod for issuer signatures and authentication for holder binding.
		expect(result.didDocument?.assertionMethod).toEqual([`${did}#0`]);
		expect(result.didDocument?.authentication).toEqual([`${did}#0`]);
	});

	it("resolves a DID URL that carries a fragment", () => {
		const did = toDidJwk(P256_JWK);
		const result = resolveDidJwk(`${did}#0`);

		expect(result.resolved).toBe(true);
		expect(result.didDocument?.id).toBe(did);
	});

	it("excludes an enc-only key from the signing relationships", () => {
		const result = resolveDidJwk(toDidJwk({ ...P256_JWK, use: "enc" }));

		expect(result.resolved).toBe(true);
		expect(result.didDocument?.assertionMethod).toEqual([]);
		expect(result.didDocument?.authentication).toEqual([]);
	});

	it("refuses a did:jwk that encodes private key material", () => {
		const result = resolveDidJwk(toDidJwk({ ...P256_JWK, d: "not-a-real-private-key" }));

		expect(result.resolved).toBe(false);
		expect(result.error).toContain("private key");
	});

	it("fails on a non-did:jwk identifier", () => {
		expect(resolveDidJwk("did:web:example.com").resolved).toBe(false);
	});

	it("fails when the method-specific id is not a JWK", () => {
		expect(resolveDidJwk(`did:jwk:${toBase64Url(new TextEncoder().encode("nonsense"))}`).resolved).toBe(false);
	});
});

describe("didWebToUrl", () => {
	it("maps a bare domain to the well-known location", () => {
		expect(didWebToUrl("did:web:example.com")).toBe("https://example.com/.well-known/did.json");
	});

	it("maps path segments to a path", () => {
		expect(didWebToUrl("did:web:example.com:org:1")).toBe("https://example.com/org/1/did.json");
	});

	it("decodes a percent-encoded port", () => {
		expect(didWebToUrl("did:web:example.com%3A3000")).toBe("https://example.com:3000/.well-known/did.json");
	});

	it("ignores a fragment", () => {
		expect(didWebToUrl("did:web:example.com#key-1")).toBe("https://example.com/.well-known/did.json");
	});

	it("returns null for other methods", () => {
		expect(didWebToUrl("did:jwk:abc")).toBeNull();
	});
});

describe("resolveDidWeb", () => {
	const didDocument: DIDDocument = {
		id: "did:web:example.com",
		verificationMethod: [{
			id: "did:web:example.com#key-1",
			type: "JsonWebKey2020",
			controller: "did:web:example.com",
			publicKeyJwk: P256_JWK as JsonWebKey,
		}],
		assertionMethod: ["did:web:example.com#key-1"],
	};

	it("fetches and returns the DID document", async () => {
		const httpClient = {
			get: vi.fn().mockResolvedValue({ status: 200, headers: {}, data: didDocument }),
			post: vi.fn(),
		};

		const result = await resolveDidWeb("did:web:example.com", httpClient);

		expect(httpClient.get).toHaveBeenCalledWith("https://example.com/.well-known/did.json", {}, { useCache: true });
		expect(result.resolved).toBe(true);
		expect(result.didDocument).toEqual(didDocument);
	});

	it("fails on a non-200 response", async () => {
		const httpClient = {
			get: vi.fn().mockResolvedValue({ status: 404, headers: {}, data: null }),
			post: vi.fn(),
		};

		expect((await resolveDidWeb("did:web:example.com", httpClient)).resolved).toBe(false);
	});

	it("fails when the fetch throws", async () => {
		const httpClient = {
			get: vi.fn().mockRejectedValue(new Error("offline")),
			post: vi.fn(),
		};

		expect((await resolveDidWeb("did:web:example.com", httpClient)).resolved).toBe(false);
	});
});

describe("createDidResolver", () => {
	it("resolves did:jwk without an HTTP client", async () => {
		const resolve = createDidResolver();
		expect((await resolve(toDidJwk(P256_JWK))).resolved).toBe(true);
	});

	it("declines did:web when no HTTP client is configured", async () => {
		const result = await createDidResolver()("did:web:example.com");
		expect(result.resolved).toBe(false);
		expect(result.error).toContain("HTTP client");
	});

	it("declines unsupported DID methods", async () => {
		expect((await createDidResolver()("did:key:z6Mk")).resolved).toBe(false);
	});
});

describe("findPublicKeyInDidDocument", () => {
	const doc: DIDDocument = {
		id: "did:web:example.com",
		verificationMethod: [
			{ id: "did:web:example.com#sig", type: "JsonWebKey2020", controller: "did:web:example.com", publicKeyJwk: P256_JWK as JsonWebKey },
			{ id: "did:web:example.com#auth", type: "JsonWebKey2020", controller: "did:web:example.com", publicKeyJwk: { ...P256_JWK, x: "other" } as JsonWebKey },
		],
		assertionMethod: ["did:web:example.com#sig"],
		authentication: ["did:web:example.com#auth"],
	};

	it("finds the key named by an absolute DID URL", () => {
		expect(findPublicKeyInDidDocument(doc, "did:web:example.com#sig", "assertionMethod")).toEqual(P256_JWK);
	});

	it("resolves a relative fragment against the document id", () => {
		expect(findPublicKeyInDidDocument(doc, "#auth", "authentication")).toMatchObject({ x: "other" });
	});

	it("falls back to the first key of the requested relationship", () => {
		expect(findPublicKeyInDidDocument(doc, "did:web:example.com", "assertionMethod")).toEqual(P256_JWK);
		expect(findPublicKeyInDidDocument(doc, "did:web:example.com", "authentication")).toMatchObject({ x: "other" });
	});

	it("returns null when the relationship is empty", () => {
		expect(findPublicKeyInDidDocument({ id: "did:web:example.com" }, "did:web:example.com", "assertionMethod")).toBeNull();
	});
});

describe("DidPublicKeyResolver", () => {
	it("resolves an issuer key from a did:jwk iss", async () => {
		const did = toDidJwk(P256_JWK);
		const result = await DidPublicKeyResolver().resolve({ identifier: did });

		expect(result.success).toBe(true);
		expect(result.success && result.value.jwk).toEqual(P256_JWK);
	});

	it("uses the kid to pick the verification method", async () => {
		const httpClient = {
			get: vi.fn().mockResolvedValue({
				status: 200,
				headers: {},
				data: {
					id: "did:web:issuer.example",
					verificationMethod: [
						{ id: "did:web:issuer.example#a", type: "JsonWebKey2020", controller: "did:web:issuer.example", publicKeyJwk: P256_JWK },
						{ id: "did:web:issuer.example#b", type: "JsonWebKey2020", controller: "did:web:issuer.example", publicKeyJwk: { ...P256_JWK, x: "second" } },
					],
					assertionMethod: ["did:web:issuer.example#a", "did:web:issuer.example#b"],
				},
			}),
			post: vi.fn(),
		};

		const result = await DidPublicKeyResolver({ httpClient }).resolve({
			identifier: "did:web:issuer.example",
			kid: "did:web:issuer.example#b",
		});

		expect(result.success && result.value.jwk).toMatchObject({ x: "second" });
	});

	it("declines identifiers that are not DIDs so other resolvers can try", async () => {
		expect((await DidPublicKeyResolver().resolve({ identifier: "https://issuer.example" })).success).toBe(false);
	});
});
