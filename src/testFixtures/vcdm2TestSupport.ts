import { vi } from "vitest";
import * as jose from "jose";
import type { Context, HttpClient, PublicKeyResolverEngineI } from "../interfaces";

/**
 * Shared scaffolding for the VCDM 2.0 tests.
 *
 * These helpers were previously copied into each test file, identically in
 * the case of makeContext and the resolver stub. Credential bodies are
 * deliberately *not* here: each test file uses its own, and moving them would
 * put the thing under test further from the assertions about it.
 */

export const subtle = globalThis.crypto.subtle;

export const VCDM2_CONTEXT = "https://www.w3.org/ns/credentials/v2";

/** base64url of a JSON value, for hand-built JWS segments. */
export function b64url(value: object): string {
	return bytesToB64Url(new TextEncoder().encode(JSON.stringify(value)));
}

export function bytesToB64Url(bytes: Uint8Array): string {
	let binary = "";
	for (const b of bytes) binary += String.fromCharCode(b);
	return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function b64ToBytes(value: string): Uint8Array {
	const binary = atob(value);
	return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

export function b64UrlToBytes(value: string): Uint8Array {
	const padded = value + "=".repeat((4 - (value.length % 4)) % 4);
	const binary = atob(padded.replace(/-/g, "+").replace(/_/g, "/"));
	return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

export function makeContext(overrides: Partial<Context> = {}): Context {
	return {
		clockTolerance: 60,
		lang: "en-US",
		subtle,
		delegateTrustToBackend: true,
		trustedCertificates: [],
		...overrides,
	} as Context;
}

/** A resolver engine that answers with `jwk` for any identifier, or fails. */
export function makeResolver(jwk: jose.JWK | null): PublicKeyResolverEngineI {
	return {
		register: vi.fn(),
		resolve: vi.fn(async () => (
			jwk
				? { success: true as const, value: { jwk } }
				: { success: false as const, error: "CannotResolvePublicKey" as any }
		)),
	} as unknown as PublicKeyResolverEngineI;
}

/** Answers 404 to everything: issuer metadata degrades to a warning. */
export const offlineHttpClient: HttpClient = {
	async get() { return { status: 404, headers: {}, data: null }; },
	async post() { return { status: 404, headers: {}, data: null }; },
};

/** Fails loudly, for paths that must never touch the network. */
export const forbiddenHttpClient: HttpClient = {
	async get() { throw new Error("network access is not expected here"); },
	async post() { throw new Error("network access is not expected here"); },
};

/** Serves issuer metadata from the well-known endpoint, 404 elsewhere. */
export function metadataHttpClient(metadata: unknown): HttpClient {
	return {
		get: vi.fn(async (url: string) => (
			url.includes("/.well-known/openid-credential-issuer")
				? { status: 200, headers: {}, data: metadata }
				: { status: 404, headers: {}, data: null }
		)),
		post: vi.fn(),
	} as unknown as HttpClient;
}

/**
 * A document loader stub. `@vocab` lets every term resolve, so jsonld's safe
 * mode is satisfied without shipping the real 30 KB VCDM 2.0 context.
 */
export function contextHttpClient(
	contextDocument: unknown = { "@context": { "@vocab": "https://example.org/vocab#" } },
): HttpClient {
	return {
		get: vi.fn(async () => ({ status: 200, headers: {}, data: contextDocument })),
		post: vi.fn(),
	} as unknown as HttpClient;
}

/** An SD-JWT whose signature is not real; enough for detection and parsing. */
export function unsignedSdJwt(
	payload: object,
	header: object = { alg: "ES256", typ: "vc+sd-jwt" },
): string {
	return `${b64url(header)}.${b64url(payload)}.sig~`;
}

/** A genuinely signed SD-JWT, returned with the key that verifies it. */
export async function signedSdJwt(payload: object, header: Record<string, unknown> = {}) {
	const { publicKey, privateKey } = await jose.generateKeyPair("ES256", { extractable: true });
	const jwt = await new jose.SignJWT(payload as jose.JWTPayload)
		.setProtectedHeader({ alg: "ES256", typ: "vc+sd-jwt", ...header })
		.sign(privateKey);
	return { raw: `${jwt}~`, publicJwk: await jose.exportJWK(publicKey) };
}

/** An enveloped (JOSE-secured) VCDM 2.0 credential with a fake signature. */
export function envelopedVcdm2(payload: object, header: object = { alg: "ES256", typ: "vc+jwt" }): string {
	return `${b64url(header)}.${b64url(payload)}.sig`;
}

/** A VCDM 1.1 token: the credential sits under a `vc` claim. */
export function vcdm11Jwt(vc: object = { type: ["VerifiableCredential"] }): string {
	return `${b64url({ alg: "ES256" })}.${b64url({ vc })}.sig`;
}
