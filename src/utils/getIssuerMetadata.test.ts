import { describe, it, assert } from "vitest";
import { getIssuerMetadata } from "../utils/getIssuerMetadata";
import { HttpClient } from "../interfaces";
import { CredentialParsingError } from "../error";
import { MetadataWarning } from "../types";
import { IAuthZENClient } from "../authzen/AuthZENClient";
import { ok, err } from "../core/Result";
import { AuthZENErrorCode } from "../authzen/types";

describe("getIssuerMetadata", () => {
	it("should warn if issuer metadata fetch fails", async () => {
		const warnings: MetadataWarning[] = [];

		const httpClient: HttpClient = {
			get: async (url: string) => {
				if (url.includes(".well-known/openid-credential-issuer")) {
					return { status: 400 };
				}
				throw new Error("Unexpected call");
			}
		};

		const result = await getIssuerMetadata(httpClient, "https://example.com", warnings);

		assert(result.metadata === null);
		assert(warnings.some(w => w.code === CredentialParsingError.FailFetchIssuerMetadata));
	});

	it("should warn if issuer metadata has invalid schema", async () => {
		const warnings: MetadataWarning[] = [];

		const httpClient: HttpClient = {
			get: async (url: string) => {
				if (url.includes(".well-known/openid-credential-issuer")) {
					return {
						status: 200,
						data: {
							invalid_field: true, // missing required schema fields
						}
					};
				}
				throw new Error("Unexpected call");
			}
		};

		const result = await getIssuerMetadata(httpClient, "https://example.com", warnings);
		assert(result.metadata === null);
		assert(warnings.some(w => w.code === CredentialParsingError.FailSchemaIssuerMetadata));
	});

	describe("resolve-based path", () => {
		const dummyHttpClient: HttpClient = {
			get: async () => { throw new Error("should not be called when authzenClient is provided"); }
		};

		function mockAuthzenClient(resolveResult: ReturnType<typeof ok | typeof err>): IAuthZENClient {
			return {
				resolve: async () => resolveResult,
				evaluate: async () => { throw new Error("not implemented"); },
				evaluateVerifier: async () => { throw new Error("not implemented"); },
				evaluateIssuer: async () => { throw new Error("not implemented"); },
			} as unknown as IAuthZENClient;
		}

		it("should return metadata from resolve response", async () => {
			const warnings: MetadataWarning[] = [];
			const client = mockAuthzenClient(ok({
				decision: true,
				context: {
					trust_metadata: {
						credential_issuer: "https://issuer.example.com",
						credential_endpoint: "https://issuer.example.com/credential",
						credential_configurations_supported: {},
					},
				},
			}));

			const result = await getIssuerMetadata(dummyHttpClient, "https://issuer.example.com", warnings, true, client);
			assert(result.metadata !== null);
			assert(result.metadata!.credential_issuer === "https://issuer.example.com");
			assert(warnings.length === 0);
		});

		it("should warn when resolve returns error", async () => {
			const warnings: MetadataWarning[] = [];
			const client = mockAuthzenClient(err({
				error: AuthZENErrorCode.NETWORK_ERROR,
				details: "timeout",
			}));

			const result = await getIssuerMetadata(dummyHttpClient, "https://issuer.example.com", warnings, true, client);
			assert(result.metadata === null);
			assert(warnings.some(w => w.code === CredentialParsingError.FailFetchIssuerMetadata));
		});

		it("should warn when resolve returns no trust_metadata", async () => {
			const warnings: MetadataWarning[] = [];
			const client = mockAuthzenClient(ok({
				decision: true,
				context: {},
			}));

			const result = await getIssuerMetadata(dummyHttpClient, "https://issuer.example.com", warnings, true, client);
			assert(result.metadata === null);
			assert(warnings.some(w => w.code === CredentialParsingError.FailFetchIssuerMetadata));
		});

		it("should warn when trust_metadata fails schema validation", async () => {
			const warnings: MetadataWarning[] = [];
			const client = mockAuthzenClient(ok({
				decision: true,
				context: {
					trust_metadata: { invalid: true },
				},
			}));

			const result = await getIssuerMetadata(dummyHttpClient, "https://issuer.example.com", warnings, true, client);
			assert(result.metadata === null);
			assert(warnings.some(w => w.code === CredentialParsingError.FailSchemaIssuerMetadata));
		});
	});
});
