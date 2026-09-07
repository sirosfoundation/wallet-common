import type { HttpClient } from "../../interfaces";

/**
 * JSON-LD document loader for Data Integrity verification.
 *
 * The `*-rdfc-*` cryptosuites canonicalize the RDF dataset, which means the
 * credential's `@context` documents have to be dereferenced. Two constraints
 * shape this loader:
 *
 *   - Contexts are fetched through the wallet's own `HttpClient`, so they go
 *     via the same proxy/OHTTP path as everything else rather than opening a
 *     side channel from the JSON-LD library.
 *   - Only an allowlist of well-known context URLs is fetched. A credential
 *     is attacker-supplied input, and an unrestricted loader would let an
 *     issuer point the wallet at arbitrary URLs during verification.
 *
 * Anything outside the allowlist fails verification rather than being fetched.
 */

/** Context URLs a VCDM 2.0 credential may legitimately reference. */
const ALLOWED_CONTEXT_URLS = new Set<string>([
	"https://www.w3.org/ns/credentials/v2",
	"https://www.w3.org/ns/credentials/examples/v2",
	"https://www.w3.org/ns/credentials/undefined-terms/v2",
	"https://www.w3.org/ns/did/v1",
	"https://w3id.org/security/data-integrity/v2",
	"https://w3id.org/security/multikey/v1",
	"https://w3id.org/security/suites/ed25519-2020/v1",
	"https://w3id.org/security/jwk/v1",
]);

export type LoadedDocument = {
	contextUrl: null;
	documentUrl: string;
	document: unknown;
};

export type DocumentLoader = (url: string) => Promise<LoadedDocument>;

/**
 * Build a document loader backed by `httpClient`, with an in-memory cache
 * shared across calls so a batch of credentials fetches each context once.
 */
export function createDocumentLoader(args: {
	httpClient: HttpClient;
	/** Extra context URLs to permit, for deployments with their own vocab. */
	additionalAllowedUrls?: Iterable<string>;
	cache?: Map<string, LoadedDocument>;
}): DocumentLoader {
	const allowed = new Set(ALLOWED_CONTEXT_URLS);
	for (const url of args.additionalAllowedUrls ?? []) allowed.add(url);

	const cache = args.cache ?? new Map<string, LoadedDocument>();

	return async (url: string): Promise<LoadedDocument> => {
		const cached = cache.get(url);
		if (cached) return cached;

		if (!allowed.has(url)) {
			throw new Error(`jsonld: refusing to load context outside the allowlist: ${url}`);
		}

		const response = await args.httpClient.get(url, { Accept: "application/ld+json, application/json" });
		if (response.status < 200 || response.status >= 300) {
			throw new Error(`jsonld: could not load context ${url} (HTTP ${response.status})`);
		}

		const document: LoadedDocument = {
			contextUrl: null,
			documentUrl: url,
			document: response.data,
		};
		cache.set(url, document);
		return document;
	};
}

export { ALLOWED_CONTEXT_URLS };
