import axios from "axios";
import { HttpClient } from "./interfaces";

/**
 * Ask for the untouched response body alongside the parsed one.
 *
 * Opt-in, because getting it means overriding axios's `transformResponse` for
 * the request, and doing that unconditionally changes what every existing
 * caller receives. Only code that needs the served octets - integrity digests,
 * see `verifySRI` - should ask.
 */
export type RawBodyOption = { wantRaw?: boolean };

/**
 * Parse the body ourselves, which is what makes the raw text available
 * alongside it. Only used when the caller asked for the raw body.
 */
function withRaw(res: { status: number; data: unknown; headers: any }) {
	const raw = typeof res.data === "string" ? res.data : undefined;
	let data: unknown = res.data;
	if (raw !== undefined) {
		try {
			data = JSON.parse(raw);
		} catch {
			// Not JSON: hand back the text, as a caller expecting a string body
			// or a non-JSON content type would have received anyway.
			data = raw;
		}
	}
	return { status: res.status, data, headers: res.headers, raw };
}

/** Axios config that suppresses its JSON parsing so the body arrives as text. */
const keepRawBody = { transformResponse: [(body: unknown) => body] };

function configFor(opts: (RawBodyOption & Record<string, unknown>) | undefined) {
	const { wantRaw, ...rest } = opts ?? {};
	return wantRaw ? { ...rest, ...keepRawBody } : rest;
}

export const defaultHttpClient: HttpClient = {
	async get(url, headers, opts) {
		const wantRaw = Boolean(opts?.wantRaw);
		return axios.get(url, { ...configFor(opts), headers: headers as any }).then((res) => (res?.data ? (wantRaw ? withRaw(res) : { status: res.status, data: res.data, headers: res.headers }) : null)).catch((err) => (err?.response?.data ? { ...err.response.data } : {}));
	},
	async post(url, data, headers, opts) {
		const wantRaw = Boolean(opts?.wantRaw);
		return axios.post(url, data, { ...configFor(opts), headers: headers as any }).then((res) => (res?.data ? (wantRaw ? withRaw(res) : { status: res.status, data: res.data, headers: res.headers }) : null)).catch((err) => (err?.response?.data ? { ...err.response.data } : {}));
	},
}
