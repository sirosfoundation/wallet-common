import { describe, expect, it, vi } from "vitest";
import { ParsingEngine } from "./ParsingEngine";
import { VCDM2JoseParser } from "./credential-parsers/VCDM2JoseParser";
import { CredentialParsingError } from "./error";
import { b64url, makeContext, offlineHttpClient } from "./testFixtures/vcdm2TestSupport";
import type { CredentialParser } from "./interfaces";

const context = makeContext();

const vcdm2Credential = {
	"@context": ["https://www.w3.org/ns/credentials/v2"],
	id: "urn:uuid:8d9f0f9c-1b1e-4a4b-9d0e-1a2b3c4d5e6f",
	type: ["VerifiableCredential", "DiplomaCredential"],
	issuer: { id: "did:example:university", name: "Example University" },
	validFrom: "2026-01-01T00:00:00Z",
	validUntil: "2027-01-01T00:00:00Z",
	credentialSubject: { id: "did:example:student", degree: "BSc" },
};

/** A VCDM 2.0 credential enveloped in a JWS (VC-JOSE-COSE). */
function envelopedVcdm2(payload: object = vcdm2Credential): string {
	return `${b64url({ alg: "ES256", typ: "vc+jwt" })}.${b64url(payload)}.signature`;
}

describe("ParsingEngine", () => {
	it("keeps trying parsers after one throws", async () => {
		const throwing: CredentialParser = {
			async parse() { throw new Error("boom"); },
		};

		const engine = ParsingEngine();
		engine.register(throwing);
		engine.register(VCDM2JoseParser({ context, httpClient: offlineHttpClient }));

		const result = await engine.parse({ rawCredential: envelopedVcdm2() });
		expect(result.success).toBe(true);
	});

	it("reports UnknownError when a parser threw and nothing else handled it", async () => {
		const throwing: CredentialParser = {
			async parse() { throw new Error("boom"); },
		};

		const engine = ParsingEngine();
		engine.register(throwing);

		const result = await engine.parse({ rawCredential: "not-a-credential" });
		expect(result.success).toBe(false);
		if (!result.success) expect(result.error).toBe(CredentialParsingError.UnknownError);
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
