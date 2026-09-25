import { describe, expect, it } from "vitest";
import { VCDM2JoseParser } from "./VCDM2JoseParser";
import { VCDM2LdpParser } from "./VCDM2LdpParser";
import { ParsingEngine } from "../ParsingEngine";
import { CredentialParsingError } from "../error";
import { VerifiableCredentialFormat } from "../types";
import { detectCredentialFormat } from "../utils/detectCredentialFormat";
import type { Context, CredentialParser, HttpClient } from "../interfaces";

/** Issuer metadata is unavailable in these tests; parsing must still succeed. */
const offlineHttpClient: HttpClient = {
	async get() { return { status: 404, headers: {}, data: null }; },
	async post() { return { status: 404, headers: {}, data: null }; },
};

const context: Context = {
	clockTolerance: 60,
	lang: "en-US",
	subtle: globalThis.crypto.subtle,
} as Context;

function b64url(value: object): string {
	const json = JSON.stringify(value);
	const bytes = new TextEncoder().encode(json);
	let binary = "";
	for (const b of bytes) binary += String.fromCharCode(b);
	return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

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
function envelopedVcdm2(typ: string | undefined = "vc+jwt"): string {
	const header = typ === undefined ? { alg: "ES256" } : { alg: "ES256", typ };
	return `${b64url(header)}.${b64url(vcdm2Credential)}.c2lnbmF0dXJl`;
}

/** A VCDM 1.1 credential, which nests the credential under a `vc` claim. */
function vcdm11Jwt(): string {
	return `${b64url({ alg: "ES256" })}.${b64url({
		iss: "did:example:issuer",
		vc: { "@context": ["https://www.w3.org/2018/credentials/v1"], type: ["VerifiableCredential"] },
	})}.c2ln`;
}

describe("VCDM2JoseParser", () => {
	const parser = VCDM2JoseParser({ context, httpClient: offlineHttpClient });

	it("parses an enveloped VCDM 2.0 credential", async () => {
		const result = await parser.parse({ rawCredential: envelopedVcdm2() });

		expect(result.success).toBe(true);
		if (!result.success) return;

		expect(result.value.metadata.credential.format).toBe(VerifiableCredentialFormat.VCDM2_JOSE);
		expect(result.value.metadata.issuer.id).toBe("did:example:university");
		expect(result.value.metadata.issuer.name).toBe("Example University");
		expect(result.value.validityInfo.validFrom).toEqual(new Date("2026-01-01T00:00:00Z"));
		expect(result.value.validityInfo.validUntil).toEqual(new Date("2027-01-01T00:00:00Z"));
	});

	it("accepts the vc-ld+jwt typ variant", async () => {
		const result = await parser.parse({ rawCredential: envelopedVcdm2("vc-ld+jwt") });
		expect(result.success).toBe(true);
	});

	it("falls back to the payload shape when typ is absent", async () => {
		const result = await parser.parse({ rawCredential: envelopedVcdm2(undefined) });
		expect(result.success).toBe(true);
	});

	it("defers on a VCDM 1.1 `vc`-wrapped JWT", async () => {
		const result = await parser.parse({ rawCredential: vcdm11Jwt() });
		expect(result.success).toBe(false);
		if (!result.success) expect(result.error).toBe(CredentialParsingError.UnsupportedFormat);
	});

	it("defers on an SD-JWT", async () => {
		const raw = `${b64url({ alg: "ES256", typ: "dc+sd-jwt" })}.${b64url({ vct: "x" })}.sig~disclosure~`;
		const result = await parser.parse({ rawCredential: raw });
		expect(result.success).toBe(false);
		if (!result.success) expect(result.error).toBe(CredentialParsingError.UnsupportedFormat);
	});

	it("prefers JWT registered claims over validFrom/validUntil when present", async () => {
		const exp = 1800000000;
		const raw = `${b64url({ alg: "ES256", typ: "vc+jwt" })}.${b64url({ ...vcdm2Credential, exp })}.sig`;
		const result = await parser.parse({ rawCredential: raw });

		expect(result.success).toBe(true);
		if (!result.success) return;
		expect(result.value.validityInfo.validUntil).toEqual(new Date(exp * 1000));
	});
});

describe("VCDM2LdpParser", () => {
	const parser = VCDM2LdpParser({ context, httpClient: offlineHttpClient });

	const ldpCredential = {
		...vcdm2Credential,
		proof: {
			type: "DataIntegrityProof",
			cryptosuite: "ecdsa-rdfc-2019",
			verificationMethod: "did:example:university#key-1",
			proofPurpose: "assertionMethod",
			proofValue: "zQeVbY4oey5q2M3XKaxup3tmzN4DRFTLVqpLMweBrSxMY2xHX5XTYV8nQApmEcqaqA3Q1gVHMrXFkXJeV6doDwLWx",
		},
	};

	it("parses a Data Integrity credential given as an object", async () => {
		const result = await parser.parse({ rawCredential: ldpCredential });

		expect(result.success).toBe(true);
		if (!result.success) return;
		expect(result.value.metadata.credential.format).toBe(VerifiableCredentialFormat.LDP_VC);
		expect(result.value.metadata.issuer.id).toBe("did:example:university");
	});

	it("parses the same credential given as JSON text, as it arrives from storage", async () => {
		const result = await parser.parse({ rawCredential: JSON.stringify(ldpCredential) });
		expect(result.success).toBe(true);
	});

	it("parses an unsigned credential, leaving the proof check to the verifier", async () => {
		const { proof: _omitted, ...unsigned } = ldpCredential;
		const result = await parser.parse({ rawCredential: unsigned });
		expect(result.success).toBe(true);
	});

	it("defers on a compact JWS", async () => {
		const result = await parser.parse({ rawCredential: envelopedVcdm2() });
		expect(result.success).toBe(false);
		if (!result.success) expect(result.error).toBe(CredentialParsingError.UnsupportedFormat);
	});

	it("defers on a VCDM 1.1 credential, which leads with the v1 context", async () => {
		const result = await parser.parse({
			rawCredential: {
				"@context": ["https://www.w3.org/2018/credentials/v1"],
				type: ["VerifiableCredential"],
				issuer: "did:example:issuer",
				credentialSubject: {},
			},
		});
		expect(result.success).toBe(false);
		if (!result.success) expect(result.error).toBe(CredentialParsingError.UnsupportedFormat);
	});
});

describe("detectCredentialFormat with VCDM 2.0", () => {
	it("detects an enveloped VCDM 2.0 credential rather than jwt_vc_json", () => {
		expect(detectCredentialFormat(envelopedVcdm2())).toBe(VerifiableCredentialFormat.VCDM2_JOSE);
	});

	it("detects a Data Integrity credential", () => {
		expect(detectCredentialFormat(JSON.stringify(vcdm2Credential))).toBe(VerifiableCredentialFormat.LDP_VC);
	});

	it("still reports a VCDM 1.1 JWT as jwt_vc_json", () => {
		expect(detectCredentialFormat(vcdm11Jwt())).toBe(VerifiableCredentialFormat.JWT_VC_JSON);
	});
});

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
