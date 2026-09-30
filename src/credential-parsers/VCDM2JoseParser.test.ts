import { describe, expect, it, vi } from "vitest";
import * as jose from "jose";
import { VCDM2JoseParser } from "./VCDM2JoseParser";
import { CredentialParsingError } from "../error";
import { VerifiableCredentialFormat } from "../types";
import {
	b64url as enc,
	b64url,
	makeContext,
	offlineHttpClient,
	subtle,
	metadataHttpClient as serveMetadata,
} from "../testFixtures/vcdm2TestSupport";
import type { Context } from "../interfaces";

const context = makeContext();

const ISSUER = "https://issuer.example";
const CONFIG_ID = "DiplomaCredential";

const vcdm2Credential = {
	"@context": ["https://www.w3.org/ns/credentials/v2"],
	id: "urn:uuid:8d9f0f9c-1b1e-4a4b-9d0e-1a2b3c4d5e6f",
	type: ["VerifiableCredential", "DiplomaCredential"],
	issuer: { id: "did:example:university", name: "Example University" },
	validFrom: "2026-01-01T00:00:00Z",
	validUntil: "2027-01-01T00:00:00Z",
	credentialSubject: { id: "did:example:student", degree: "BSc" },
};

const genericCredential = {
	"@context": ["https://www.w3.org/ns/credentials/v2"],
	// Only the generic type, so the display name must fall back.
	type: ["VerifiableCredential"],
	issuer: "did:example:issuer",
	credentialSubject: { id: "did:example:subject" },
};

const credentialBody = {
	"@context": ["https://www.w3.org/ns/credentials/v2"],
	type: ["VerifiableCredential", "DiplomaCredential"],
	issuer: ISSUER,
	credentialSubject: { id: "did:example:subject", degree: "BSc" },
};

const issuerMetadata = {
	credential_issuer: ISSUER,
	credential_endpoint: `${ISSUER}/credential`,
	credential_configurations_supported: {
		[CONFIG_ID]: {
			format: "vc+jwt",
			scope: "diploma",
			credential_metadata: {
				display: [{
					name: "Diploma",
					locale: "en-US",
					background_color: "#ffffff",
					text_color: "#000000",
				}],
				claims: [
					{ path: ["degree"], display: [{ name: "Degree", locale: "en-US" }] },
				],
			},
		},
	},
};

/** Serves this file's issuer metadata unless a different document is given. */
const metadataHttpClient = (metadata: unknown = issuerMetadata) => serveMetadata(metadata);

/** A VCDM 2.0 credential enveloped in a JWS (VC-JOSE-COSE). */
function envelopedVcdm2(typ: string | undefined = "vc+jwt"): string {
	const header = typ === undefined ? { alg: "ES256" } : { alg: "ES256", typ };
	return `${b64url(header)}.${b64url(vcdm2Credential)}.c2lnbmF0dXJl`;
}

function vcdm11Jwt(): string {
	return `${b64url({ alg: "ES256" })}.${b64url({ vc: { type: ["VerifiableCredential"] } })}.signature`;
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

describe("VCDM2JoseParser with issuer metadata", () => {
	const raw = `${enc({ alg: "ES256", typ: "vc+jwt" })}.${enc(credentialBody)}.sig`;

	it("applies display and claim metadata from the issuer's configuration", async () => {
		const parser = VCDM2JoseParser({ context: makeContext(), httpClient: metadataHttpClient() });

		const result = await parser.parse({
			rawCredential: raw,
			credentialIssuer: { credentialIssuerIdentifier: ISSUER, credentialConfigurationId: CONFIG_ID },
		});

		expect(result.success).toBe(true);
		if (!result.success) return;

		const credential = result.value.metadata.credential;
		expect(credential.TypeMetadata.claims?.length).toBeGreaterThan(0);
		expect(await credential.name(["en-US"])).toBe("Diploma");
		expect(await credential.rendering(["en-US"])).toMatchObject({ backgroundColor: "#ffffff" });
	});

	it("falls back to the credential's own type when no configuration id is given", async () => {
		const parser = VCDM2JoseParser({ context: makeContext(), httpClient: metadataHttpClient() });

		const result = await parser.parse({ rawCredential: raw });
		expect(result.success).toBe(true);
		if (!result.success) return;
		expect(await result.value.metadata.credential.name(["en-US"])).toBe("DiplomaCredential");
	});

	it("tolerates a configuration whose metadata has no claims", async () => {
		const withoutClaims = {
			...issuerMetadata,
			credential_configurations_supported: {
				[CONFIG_ID]: { format: "vc+jwt", scope: "diploma", credential_metadata: { display: [{ name: "Diploma", locale: "en-US" }] } },
			},
		};
		const parser = VCDM2JoseParser({ context: makeContext(), httpClient: metadataHttpClient(withoutClaims) });

		const result = await parser.parse({
			rawCredential: raw,
			credentialIssuer: { credentialIssuerIdentifier: ISSUER, credentialConfigurationId: CONFIG_ID },
		});
		expect(result.success).toBe(true);
		if (result.success) expect(result.value.metadata.credential.TypeMetadata.claims).toBeUndefined();
	});

	it("reports a header without an alg as unparseable", async () => {
		const parser = VCDM2JoseParser({ context: makeContext(), httpClient: metadataHttpClient() });
		const noAlg = `${enc({ typ: "vc+jwt" })}.${enc(credentialBody)}.sig`;

		const result = await parser.parse({ rawCredential: noAlg });
		expect(result.success).toBe(false);
		if (!result.success) expect(result.error).toBe(CredentialParsingError.CouldNotParse);
	});

	it("reports a payload that is not a valid VCDM 2.0 credential", async () => {
		const parser = VCDM2JoseParser({ context: makeContext(), httpClient: metadataHttpClient() });
		// `typ` claims VCDM 2.0, but the payload has no context/type/issuer.
		const bad = `${enc({ alg: "ES256", typ: "vc+jwt" })}.${enc({ hello: "world" })}.sig`;

		const result = await parser.parse({ rawCredential: bad });
		expect(result.success).toBe(false);
		if (!result.success) expect(result.error).toBe(CredentialParsingError.InvalidVcdm2Credential);
	});
});

describe("VCDM2JoseParser display name fallback", () => {
	it("VCDM2JoseParser names a credential with only the generic type", async () => {
		const parser = VCDM2JoseParser({ context: { subtle } as Context, httpClient: offlineHttpClient });
		const raw = `${enc({ alg: "ES256", typ: "vc+jwt" })}.${enc(genericCredential)}.sig`;

		const result = await parser.parse({ rawCredential: raw });
		expect(result.success).toBe(true);
		if (result.success) expect(await result.value.metadata.credential.name()).toBe("Verifiable Credential");
	});
});

describe("VCDM2JoseParser JWT registered claims", () => {
	it("carries iat and nbf through to validity info", async () => {
		const parser = VCDM2JoseParser({ context: { subtle } as Context, httpClient: offlineHttpClient });
		const raw = `${enc({ alg: "ES256", typ: "vc+jwt" })}.${enc({
			...genericCredential, iat: 1700000000, nbf: 1700000001,
		})}.sig`;

		const result = await parser.parse({ rawCredential: raw });
		expect(result.success).toBe(true);
		if (!result.success) return;
		expect(result.value.validityInfo.signed).toEqual(new Date(1700000000 * 1000));
		expect(result.value.validityInfo.validFrom).toEqual(new Date(1700000001 * 1000));
	});
});
