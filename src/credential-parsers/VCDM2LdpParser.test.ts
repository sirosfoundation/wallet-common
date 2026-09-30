import { describe, expect, it } from "vitest";
import { VCDM2LdpParser } from "./VCDM2LdpParser";
import { CredentialParsingError } from "../error";
import { VerifiableCredentialFormat } from "../types";
import type { Context } from "../interfaces";
import {
	makeContext,
	offlineHttpClient,
	metadataHttpClient as serveMetadata,
	b64url,
	subtle,
} from "../testFixtures/vcdm2TestSupport";

const context = makeContext();

const genericCredential = {
	"@context": ["https://www.w3.org/ns/credentials/v2"],
	// Only the generic type, so the display name must fall back.
	type: ["VerifiableCredential"],
	issuer: "did:example:issuer",
	credentialSubject: { id: "did:example:subject" },
};

/** A VCDM 2.0 credential enveloped in a JWS: this parser must defer on it. */
function envelopedVcdm2(payload: object = vcdm2Credential): string {
	return `${b64url({ alg: "ES256", typ: "vc+jwt" })}.${b64url(payload)}.signature`;
}

const ISSUER = "https://issuer.example.com";
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

describe("VCDM2LdpParser with issuer metadata", () => {
	it("applies display and claim metadata", async () => {
		const parser = VCDM2LdpParser({ context: makeContext(), httpClient: metadataHttpClient() });

		const result = await parser.parse({
			rawCredential: credentialBody,
			credentialIssuer: { credentialIssuerIdentifier: ISSUER, credentialConfigurationId: CONFIG_ID },
		});

		expect(result.success).toBe(true);
		if (!result.success) return;
		expect(result.value.metadata.credential.TypeMetadata.claims?.length).toBeGreaterThan(0);
		expect(await result.value.metadata.credential.name(["en-US"])).toBe("Diploma");
	});

	it("tolerates a configuration whose metadata has no claims", async () => {
		const withoutClaims = {
			...issuerMetadata,
			credential_configurations_supported: {
				[CONFIG_ID]: { format: "ldp_vc", scope: "diploma", credential_metadata: { display: [{ name: "Diploma", locale: "en-US" }] } },
			},
		};
		const parser = VCDM2LdpParser({ context: makeContext(), httpClient: metadataHttpClient(withoutClaims) });

		const result = await parser.parse({
			rawCredential: credentialBody,
			credentialIssuer: { credentialIssuerIdentifier: ISSUER, credentialConfigurationId: CONFIG_ID },
		});
		expect(result.success).toBe(true);
	});

	it("reports a credential that is structurally VCDM 2.0 but fails the schema", async () => {
		const parser = VCDM2LdpParser({ context: makeContext(), httpClient: metadataHttpClient() });

		const result = await parser.parse({
			rawCredential: {
				"@context": ["https://www.w3.org/ns/credentials/v2"],
				type: ["VerifiableCredential"],
				issuer: 42,
				credentialSubject: {},
			},
		});

		expect(result.success).toBe(false);
		if (!result.success) expect(result.error).toBe(CredentialParsingError.InvalidVcdm2Credential);
	});
});

describe("VCDM2LdpParser display name fallback", () => {
	it("names a credential with only the generic type", async () => {
		const parser = VCDM2LdpParser({ context: { subtle } as Context, httpClient: offlineHttpClient });

		const result = await parser.parse({ rawCredential: genericCredential });
		expect(result.success).toBe(true);
		if (result.success) expect(await result.value.metadata.credential.name()).toBe("Verifiable Credential");
	});
});
