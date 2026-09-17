/**
 * IETF Token Status List — the revocation mechanism DIIP v5 mandates.
 *
 * A credential carries a `status.status_list` reference: an index plus the URI of a Status List
 * Token. That token is a JWS (`typ: statuslist+jwt`) whose payload holds a zlib-compressed bit
 * array; the bits at the credential's index encode its status.
 *
 * @see https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/15/
 */

import { JWK, importJWK, importX509, jwtVerify } from "jose";
import { HttpClient } from "../interfaces";
import { fromBase64Url } from "./util";

/** Status values registered by the Token Status List draft. */
export enum TokenStatus {
	VALID = 0x00,
	INVALID = 0x01,
	SUSPENDED = 0x02,
}

/** The `status.status_list` object embedded in a credential. */
export type StatusListReference = {
	idx: number;
	uri: string;
};

export type StatusListResolution =
	| { ok: true; status: TokenStatus }
	/**
	 * The status could not be established — typically the list was unreachable. Callers should
	 * treat this as a warning rather than a hard failure so an offline wallet stays usable.
	 */
	| { ok: false; reason: string };

const decoder = new TextDecoder();

/**
 * Read the Status List reference out of a credential's claims, if it has one.
 */
export function extractStatusListReference(claims: unknown): StatusListReference | null {
	if (typeof claims !== "object" || claims === null) {
		return null;
	}
	const status = (claims as { status?: { status_list?: unknown } }).status;
	const statusList = status?.status_list;
	if (typeof statusList !== "object" || statusList === null) {
		return null;
	}
	const { idx, uri } = statusList as { idx?: unknown; uri?: unknown };
	if (typeof idx !== "number" || !Number.isInteger(idx) || idx < 0 || typeof uri !== "string" || !uri) {
		return null;
	}
	return { idx, uri };
}

/**
 * Inflate the zlib-compressed status list. Uses the platform's `DecompressionStream`, which both
 * browsers and Node provide, rather than pulling in a compression dependency.
 */
async function inflate(compressed: Uint8Array): Promise<Uint8Array> {
	if (typeof DecompressionStream === "undefined") {
		throw new Error("DecompressionStream is not available in this runtime");
	}
	const stream = new Blob([compressed as BlobPart]).stream().pipeThrough(new DecompressionStream("deflate"));
	return new Uint8Array(await new Response(stream).arrayBuffer());
}

/**
 * Read the status at `idx` from a decompressed status list.
 *
 * Entries are packed `bits` at a time, least significant bits first within each byte.
 */
export function readStatusAtIndex(list: Uint8Array, bits: number, idx: number): number | null {
	if (![1, 2, 4, 8].includes(bits)) {
		return null;
	}
	const entriesPerByte = 8 / bits;
	const byteIndex = Math.floor(idx / entriesPerByte);
	if (byteIndex >= list.length) {
		return null;
	}
	const shift = (idx % entriesPerByte) * bits;
	const mask = (1 << bits) - 1;
	return (list[byteIndex] >> shift) & mask;
}

/**
 * Decode a verified Status List Token payload into its bit array and entry width.
 */
export function decodeStatusListPayload(payload: unknown): { bits: number; lst: string } | null {
	if (typeof payload !== "object" || payload === null) {
		return null;
	}
	const statusList = (payload as { status_list?: unknown }).status_list;
	if (typeof statusList !== "object" || statusList === null) {
		return null;
	}
	const { bits, lst } = statusList as { bits?: unknown; lst?: unknown };
	if (typeof bits !== "number" || typeof lst !== "string") {
		return null;
	}
	return { bits, lst };
}

export type StatusListKeyResolver = (args: { identifier: string; kid?: string }) => Promise<JWK | null>;

export type ResolveTokenStatusArgs = {
	reference: StatusListReference;
	httpClient: HttpClient;
	/**
	 * Issuer of the credential being checked. The Status List Token's `iss` must match it,
	 * otherwise anyone could serve a status list for someone else's credentials.
	 */
	expectedIssuer?: string;
	/** Resolves the Status List Token's signing key when its header carries no `x5c`. */
	resolveKey?: StatusListKeyResolver;
	clockTolerance?: number;
	/** Cache shared across checks so one list is fetched once per session. */
	cache?: StatusListCache;
};

/**
 * A small cache of fetched status lists, keyed by URI.
 *
 * Status List Tokens carry a `ttl`; entries are re-fetched once it lapses.
 */
export type StatusListCache = Map<string, { fetchedAt: number; ttl: number; bits: number; list: Uint8Array }>;

export function createStatusListCache(): StatusListCache {
	return new Map();
}

/**
 * Fetch, verify and read a credential's entry in its Status List.
 */
export async function resolveTokenStatus(args: ResolveTokenStatusArgs): Promise<StatusListResolution> {
	const { reference, httpClient, expectedIssuer, resolveKey, clockTolerance = 0, cache } = args;

	const cached = cache?.get(reference.uri);
	if (cached && (cached.ttl <= 0 || Date.now() - cached.fetchedAt < cached.ttl * 1000)) {
		const status = readStatusAtIndex(cached.list, cached.bits, reference.idx);
		return status === null
			? { ok: false, reason: `Index ${reference.idx} is outside the cached status list` }
			: { ok: true, status };
	}

	let token: string;
	try {
		const response = await httpClient.get(reference.uri, { Accept: "application/statuslist+jwt" });
		if (response.status !== 200 || typeof response.data !== "string") {
			return { ok: false, reason: `Status list at ${reference.uri} returned status ${response.status}` };
		}
		token = response.data;
	}
	catch (err) {
		return { ok: false, reason: `Could not fetch the status list at ${reference.uri}: ${err}` };
	}

	const [rawHeader] = token.split(".");
	let header: { alg?: string; kid?: string; typ?: string; x5c?: string[] };
	try {
		header = JSON.parse(decoder.decode(fromBase64Url(rawHeader)));
	}
	catch {
		return { ok: false, reason: "Status List Token header is not valid JSON" };
	}

	// draft-ietf-oauth-status-list §5.1: the token is typed to stop it being confused with
	// any other JWS the issuer signs.
	if (header.typ !== "statuslist+jwt") {
		return { ok: false, reason: `Unexpected Status List Token typ: ${header.typ}` };
	}

	let key: Awaited<ReturnType<typeof importJWK>> | null = null;
	try {
		if (header.x5c?.length) {
			key = await importX509(
				`-----BEGIN CERTIFICATE-----\n${header.x5c[0].match(/.{1,64}/g)?.join("\n")}\n-----END CERTIFICATE-----`,
				header.alg ?? "ES256",
			);
		}
		else if (resolveKey && expectedIssuer) {
			const jwk = await resolveKey({ identifier: expectedIssuer, kid: header.kid });
			key = jwk ? await importJWK(jwk, header.alg ?? "ES256") : null;
		}
	}
	catch (err) {
		return { ok: false, reason: `Could not import the Status List Token signing key: ${err}` };
	}

	if (!key) {
		return { ok: false, reason: "No signing key available for the Status List Token" };
	}

	let payload: Record<string, unknown>;
	try {
		({ payload } = await jwtVerify(token, key, { clockTolerance }));
	}
	catch (err) {
		return { ok: false, reason: `Status List Token signature verification failed: ${err}` };
	}

	if (expectedIssuer && payload.iss !== expectedIssuer) {
		return { ok: false, reason: `Status List Token was issued by ${payload.iss}, expected ${expectedIssuer}` };
	}
	// §5.1: `sub` binds the token to the URI it was served from.
	if (typeof payload.sub === "string" && payload.sub !== reference.uri) {
		return { ok: false, reason: `Status List Token subject ${payload.sub} does not match ${reference.uri}` };
	}

	const decoded = decodeStatusListPayload(payload);
	if (!decoded) {
		return { ok: false, reason: "Status List Token has no usable status_list claim" };
	}

	let list: Uint8Array;
	try {
		list = await inflate(fromBase64Url(decoded.lst));
	}
	catch (err) {
		return { ok: false, reason: `Could not decompress the status list: ${err}` };
	}

	cache?.set(reference.uri, {
		fetchedAt: Date.now(),
		ttl: typeof payload.ttl === "number" ? payload.ttl : 0,
		bits: decoded.bits,
		list,
	});

	const status = readStatusAtIndex(list, decoded.bits, reference.idx);
	return status === null
		? { ok: false, reason: `Index ${reference.idx} is outside the status list` }
		: { ok: true, status };
}
