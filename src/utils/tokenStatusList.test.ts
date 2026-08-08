import { describe, expect, it, vi } from "vitest";
import { SignJWT, exportJWK, generateKeyPair } from "jose";
import {
	TokenStatus,
	createStatusListCache,
	decodeStatusListPayload,
	extractStatusListReference,
	readStatusAtIndex,
	resolveTokenStatus,
} from "./tokenStatusList";
import { toBase64Url } from "./util";

const ISSUER = "https://issuer.example";
const LIST_URI = "https://issuer.example/statuslists/1";

/** zlib-compress a byte array the way a Status List Token issuer would. */
async function deflate(bytes: Uint8Array): Promise<Uint8Array> {
	const stream = new Blob([bytes as BlobPart]).stream().pipeThrough(new CompressionStream("deflate"));
	return new Uint8Array(await new Response(stream).arrayBuffer());
}

/**
 * Build a signed Status List Token over the given statuses.
 */
async function buildStatusListToken(statuses: number[], bits: 1 | 2 | 4 | 8, overrides: Record<string, unknown> = {}) {
	const { privateKey, publicKey } = await generateKeyPair("ES256", { extractable: true });
	const entriesPerByte = 8 / bits;
	const list = new Uint8Array(Math.ceil(statuses.length / entriesPerByte));
	statuses.forEach((status, idx) => {
		list[Math.floor(idx / entriesPerByte)] |= (status & ((1 << bits) - 1)) << ((idx % entriesPerByte) * bits);
	});

	const token = await new SignJWT({
		status_list: { bits, lst: toBase64Url(await deflate(list)) },
		...overrides,
	})
		.setProtectedHeader({ alg: "ES256", typ: "statuslist+jwt" })
		.setIssuer(ISSUER)
		.setSubject(LIST_URI)
		.setIssuedAt()
		.sign(privateKey);

	return { token, publicJwk: await exportJWK(publicKey) };
}

const httpClientReturning = (token: string) => ({
	get: vi.fn().mockResolvedValue({ status: 200, headers: {}, data: token }),
	post: vi.fn(),
});

describe("extractStatusListReference", () => {
	it("reads a well-formed reference", () => {
		expect(extractStatusListReference({ status: { status_list: { idx: 42, uri: LIST_URI } } }))
			.toEqual({ idx: 42, uri: LIST_URI });
	});

	it("accepts index zero", () => {
		expect(extractStatusListReference({ status: { status_list: { idx: 0, uri: LIST_URI } } })?.idx).toBe(0);
	});

	it("returns null when there is no status claim", () => {
		expect(extractStatusListReference({ vct: "urn:example" })).toBeNull();
		expect(extractStatusListReference(null)).toBeNull();
		expect(extractStatusListReference({ status: {} })).toBeNull();
	});

	it("rejects malformed references", () => {
		expect(extractStatusListReference({ status: { status_list: { idx: -1, uri: LIST_URI } } })).toBeNull();
		expect(extractStatusListReference({ status: { status_list: { idx: 1.5, uri: LIST_URI } } })).toBeNull();
		expect(extractStatusListReference({ status: { status_list: { idx: 1, uri: "" } } })).toBeNull();
		expect(extractStatusListReference({ status: { status_list: { idx: "1", uri: LIST_URI } } })).toBeNull();
	});
});

describe("readStatusAtIndex", () => {
	it("reads 1-bit entries least-significant-bit first", () => {
		// 0b00000101 -> entries 0 and 2 are set.
		const list = new Uint8Array([0b00000101]);

		expect(readStatusAtIndex(list, 1, 0)).toBe(1);
		expect(readStatusAtIndex(list, 1, 1)).toBe(0);
		expect(readStatusAtIndex(list, 1, 2)).toBe(1);
		expect(readStatusAtIndex(list, 1, 7)).toBe(0);
	});

	it("reads 2-bit entries", () => {
		// 0b11100100 -> entries 0..3 are 0, 1, 2, 3.
		const list = new Uint8Array([0b11100100]);

		expect([0, 1, 2, 3].map((i) => readStatusAtIndex(list, 2, i))).toEqual([0, 1, 2, 3]);
	});

	it("reads 4-bit and 8-bit entries", () => {
		expect(readStatusAtIndex(new Uint8Array([0xA5]), 4, 0)).toBe(0x5);
		expect(readStatusAtIndex(new Uint8Array([0xA5]), 4, 1)).toBe(0xA);
		expect(readStatusAtIndex(new Uint8Array([0xA5, 0x3C]), 8, 1)).toBe(0x3C);
	});

	it("spans byte boundaries", () => {
		expect(readStatusAtIndex(new Uint8Array([0x00, 0b00000010]), 1, 9)).toBe(1);
	});

	it("returns null for an out-of-range index or unsupported width", () => {
		expect(readStatusAtIndex(new Uint8Array([0x00]), 1, 8)).toBeNull();
		expect(readStatusAtIndex(new Uint8Array([0x00]), 3, 0)).toBeNull();
	});
});

describe("decodeStatusListPayload", () => {
	it("reads bits and lst", () => {
		expect(decodeStatusListPayload({ status_list: { bits: 1, lst: "abc" } })).toEqual({ bits: 1, lst: "abc" });
	});

	it("returns null when the claim is missing or malformed", () => {
		expect(decodeStatusListPayload({})).toBeNull();
		expect(decodeStatusListPayload({ status_list: { bits: "1", lst: "abc" } })).toBeNull();
	});
});

describe("resolveTokenStatus", () => {
	const resolveKeyFor = (jwk: unknown) => async () => jwk as never;

	it("reports a valid credential", async () => {
		const { token, publicJwk } = await buildStatusListToken([TokenStatus.VALID, TokenStatus.INVALID], 1);

		const result = await resolveTokenStatus({
			reference: { idx: 0, uri: LIST_URI },
			httpClient: httpClientReturning(token),
			expectedIssuer: ISSUER,
			resolveKey: resolveKeyFor(publicJwk),
		});

		expect(result).toEqual({ ok: true, status: TokenStatus.VALID });
	});

	it("reports a revoked credential", async () => {
		const { token, publicJwk } = await buildStatusListToken([TokenStatus.VALID, TokenStatus.INVALID], 1);

		const result = await resolveTokenStatus({
			reference: { idx: 1, uri: LIST_URI },
			httpClient: httpClientReturning(token),
			expectedIssuer: ISSUER,
			resolveKey: resolveKeyFor(publicJwk),
		});

		expect(result).toEqual({ ok: true, status: TokenStatus.INVALID });
	});

	it("reports a suspended credential from a 2-bit list", async () => {
		const { token, publicJwk } = await buildStatusListToken(
			[TokenStatus.VALID, TokenStatus.SUSPENDED, TokenStatus.INVALID],
			2,
		);

		const result = await resolveTokenStatus({
			reference: { idx: 1, uri: LIST_URI },
			httpClient: httpClientReturning(token),
			expectedIssuer: ISSUER,
			resolveKey: resolveKeyFor(publicJwk),
		});

		expect(result).toEqual({ ok: true, status: TokenStatus.SUSPENDED });
	});

	it("does not fail hard when the status list is unreachable", async () => {
		const httpClient = { get: vi.fn().mockRejectedValue(new Error("offline")), post: vi.fn() };

		const result = await resolveTokenStatus({
			reference: { idx: 0, uri: LIST_URI },
			httpClient,
			expectedIssuer: ISSUER,
		});

		expect(result.ok).toBe(false);
		expect(result.ok === false && result.reason).toContain("Could not fetch");
	});

	it("rejects a token with the wrong typ", async () => {
		const { privateKey, publicKey } = await generateKeyPair("ES256", { extractable: true });
		const token = await new SignJWT({ status_list: { bits: 1, lst: "" } })
			.setProtectedHeader({ alg: "ES256", typ: "JWT" })
			.setIssuer(ISSUER)
			.sign(privateKey);

		const result = await resolveTokenStatus({
			reference: { idx: 0, uri: LIST_URI },
			httpClient: httpClientReturning(token),
			expectedIssuer: ISSUER,
			resolveKey: resolveKeyFor(await exportJWK(publicKey)),
		});

		expect(result.ok).toBe(false);
		expect(result.ok === false && result.reason).toContain("typ");
	});

	it("rejects a status list issued by someone other than the credential issuer", async () => {
		const { token, publicJwk } = await buildStatusListToken([TokenStatus.INVALID], 1);

		const result = await resolveTokenStatus({
			reference: { idx: 0, uri: LIST_URI },
			httpClient: httpClientReturning(token),
			expectedIssuer: "https://attacker.example",
			resolveKey: resolveKeyFor(publicJwk),
		});

		expect(result.ok).toBe(false);
		expect(result.ok === false && result.reason).toContain("issued by");
	});

	it("rejects a token whose subject does not match the list URI", async () => {
		const { privateKey, publicKey } = await generateKeyPair("ES256", { extractable: true });
		const token = await new SignJWT({ status_list: { bits: 1, lst: toBase64Url(await deflate(new Uint8Array([0]))) } })
			.setProtectedHeader({ alg: "ES256", typ: "statuslist+jwt" })
			.setIssuer(ISSUER)
			.setSubject("https://issuer.example/statuslists/other")
			.sign(privateKey);

		const result = await resolveTokenStatus({
			reference: { idx: 0, uri: LIST_URI },
			httpClient: httpClientReturning(token),
			expectedIssuer: ISSUER,
			resolveKey: resolveKeyFor(await exportJWK(publicKey)),
		});

		expect(result.ok).toBe(false);
		expect(result.ok === false && result.reason).toContain("subject");
	});

	it("rejects an index beyond the end of the list", async () => {
		const { token, publicJwk } = await buildStatusListToken([TokenStatus.VALID], 1);

		const result = await resolveTokenStatus({
			reference: { idx: 5000, uri: LIST_URI },
			httpClient: httpClientReturning(token),
			expectedIssuer: ISSUER,
			resolveKey: resolveKeyFor(publicJwk),
		});

		expect(result.ok).toBe(false);
		expect(result.ok === false && result.reason).toContain("outside");
	});

	it("serves a second lookup from the cache while the ttl holds", async () => {
		const { token, publicJwk } = await buildStatusListToken(
			[TokenStatus.VALID, TokenStatus.INVALID],
			1,
			{ ttl: 3600 },
		);
		const httpClient = httpClientReturning(token);
		const cache = createStatusListCache();
		const common = {
			httpClient,
			expectedIssuer: ISSUER,
			resolveKey: resolveKeyFor(publicJwk),
			cache,
		};

		expect(await resolveTokenStatus({ ...common, reference: { idx: 0, uri: LIST_URI } }))
			.toEqual({ ok: true, status: TokenStatus.VALID });
		expect(await resolveTokenStatus({ ...common, reference: { idx: 1, uri: LIST_URI } }))
			.toEqual({ ok: true, status: TokenStatus.INVALID });

		expect(httpClient.get).toHaveBeenCalledTimes(1);
	});

	it("fails when no signing key can be obtained", async () => {
		const { token } = await buildStatusListToken([TokenStatus.VALID], 1);

		const result = await resolveTokenStatus({
			reference: { idx: 0, uri: LIST_URI },
			httpClient: httpClientReturning(token),
			expectedIssuer: ISSUER,
		});

		expect(result.ok).toBe(false);
		expect(result.ok === false && result.reason).toContain("No signing key");
	});
});
