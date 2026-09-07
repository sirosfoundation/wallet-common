import { describe, expect, it, vi } from "vitest";
import { ALLOWED_CONTEXT_URLS, createDocumentLoader } from "./documentLoader";
import type { HttpClient } from "../../interfaces";

const VCDM2_CONTEXT = "https://www.w3.org/ns/credentials/v2";

function stubHttpClient(response: { status: number; data?: unknown }): HttpClient & { get: ReturnType<typeof vi.fn> } {
	const get = vi.fn(async () => ({ status: response.status, headers: {}, data: response.data ?? null }));
	return { get, post: vi.fn() } as unknown as HttpClient & { get: ReturnType<typeof vi.fn> };
}

describe("createDocumentLoader", () => {
	it("loads an allowlisted context and returns it in JSON-LD loader shape", async () => {
		const httpClient = stubHttpClient({ status: 200, data: { "@context": {} } });
		const load = createDocumentLoader({ httpClient });

		const result = await load(VCDM2_CONTEXT);

		expect(result.documentUrl).toBe(VCDM2_CONTEXT);
		expect(result.contextUrl).toBeNull();
		expect(result.document).toEqual({ "@context": {} });
		expect(httpClient.get).toHaveBeenCalledWith(
			VCDM2_CONTEXT,
			{ Accept: "application/ld+json, application/json" },
		);
	});

	it("refuses a context outside the allowlist without touching the network", async () => {
		const httpClient = stubHttpClient({ status: 200 });
		const load = createDocumentLoader({ httpClient });

		await expect(load("https://evil.example/context.jsonld")).rejects.toThrow(/allowlist/);
		expect(httpClient.get).not.toHaveBeenCalled();
	});

	it("permits additional context URLs when a deployment supplies them", async () => {
		const httpClient = stubHttpClient({ status: 200, data: { ok: true } });
		const load = createDocumentLoader({
			httpClient,
			additionalAllowedUrls: ["https://vocab.example/v1"],
		});

		const result = await load("https://vocab.example/v1");
		expect(result.document).toEqual({ ok: true });
	});

	it("surfaces a non-2xx response as an error", async () => {
		const httpClient = stubHttpClient({ status: 503 });
		const load = createDocumentLoader({ httpClient });

		await expect(load(VCDM2_CONTEXT)).rejects.toThrow(/HTTP 503/);
	});

	it("caches a loaded context so it is fetched only once", async () => {
		const httpClient = stubHttpClient({ status: 200, data: { "@context": {} } });
		const load = createDocumentLoader({ httpClient });

		await load(VCDM2_CONTEXT);
		await load(VCDM2_CONTEXT);

		expect(httpClient.get).toHaveBeenCalledTimes(1);
	});

	it("shares an externally supplied cache across loaders", async () => {
		const cache = new Map();
		const first = stubHttpClient({ status: 200, data: { "@context": {} } });
		const second = stubHttpClient({ status: 200, data: { "@context": {} } });

		await createDocumentLoader({ httpClient: first, cache })(VCDM2_CONTEXT);
		await createDocumentLoader({ httpClient: second, cache })(VCDM2_CONTEXT);

		expect(first.get).toHaveBeenCalledTimes(1);
		expect(second.get).not.toHaveBeenCalled();
	});

	it("allowlists the VCDM 2.0 and Data Integrity contexts", () => {
		expect(ALLOWED_CONTEXT_URLS.has(VCDM2_CONTEXT)).toBe(true);
		expect(ALLOWED_CONTEXT_URLS.has("https://w3id.org/security/data-integrity/v2")).toBe(true);
	});
});
