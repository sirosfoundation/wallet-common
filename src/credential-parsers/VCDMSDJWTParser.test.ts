import { describe, expect, it } from "vitest";
import Crypto from "node:crypto";
import { Jwt, SDJwt } from "@sd-jwt/core";
import { VCDMSDJWTParser } from "./VCDMSDJWTParser";
import { SDJWTVCParser } from "./SDJWTVCParser";
import { Context, HttpClient } from "../interfaces";
import { CredentialParsingError } from "../error";
import { VerifiableCredentialFormat } from "../types";
import { detectCredentialFormat } from "../utils/detectCredentialFormat";

/**
 * Build an SD-JWT with the given claims set, the way VC-JOSE-COSE §3.2.1 secures a
 * W3C VCDM 2.0 credential: the credential *is* the JWT Claims Set.
 */
const buildSdJwt = async (payload: Record<string, unknown>, typ = "vc+sd-jwt") => {
	const { privateKey } = Crypto.generateKeyPairSync("ed25519");
	const signer = async (data: string) => Buffer.from(Crypto.sign(null, Buffer.from(data), privateKey)).toString("base64url");
	const jwt = new Jwt({ header: { alg: "EdDSA", typ }, payload });
	await jwt.sign(signer);
	return new SDJwt({ jwt, disclosures: [] }).encodeSDJwt();
};

const VCDM_CREDENTIAL = {
	"@context": ["https://www.w3.org/ns/credentials/v2"],
	type: ["VerifiableCredential", "OpenBadgeCredential"],
	issuer: "did:web:issuer.example",
	validFrom: "2026-01-01T00:00:00Z",
	validUntil: "2027-01-01T00:00:00Z",
	name: "Advanced Welding Certificate",
	credentialSubject: { id: "did:jwk:eyJrdHkiOiJFQyJ9", achievement: "Welding" },
	iat: 1767225600,
};

// The issuer metadata lookup is not what these tests exercise; fail every fetch so the
// parser falls back to the credential's own display information.
const httpClient: HttpClient = {
	get: async () => { throw new Error("no network in tests"); },
	post: async () => { throw new Error("no network in tests"); },
};

const context = {
	clockTolerance: 60,
	subtle: Crypto.webcrypto.subtle,
	lang: "en-US",
	trustedCertificates: [],
} as unknown as Context;

const parser = () => VCDMSDJWTParser({ context, httpClient });

describe("VCDMSDJWTParser", () => {
	it("parses a W3C VCDM 2.0 credential secured with SD-JWT", async () => {
		const raw = await buildSdJwt(VCDM_CREDENTIAL);

		const result = await parser().parse({ rawCredential: raw });

		expect(result.success).toBe(true);
		if (!result.success) return;

		const credential = result.value.metadata.credential;
		expect(credential.format).toBe(VerifiableCredentialFormat.W3C_VCDM_SDJWT);
		expect(credential.format === VerifiableCredentialFormat.W3C_VCDM_SDJWT && credential.type)
			.toEqual(["VerifiableCredential", "OpenBadgeCredential"]);
		expect(credential.format === VerifiableCredentialFormat.W3C_VCDM_SDJWT && credential.context)
			.toEqual(["https://www.w3.org/ns/credentials/v2"]);
		expect(result.value.metadata.issuer.id).toBe("did:web:issuer.example");
		expect(result.value.signedClaims.credentialSubject).toMatchObject({ achievement: "Welding" });
	});

	it("surfaces the VCDM validity window", async () => {
		const result = await parser().parse({ rawCredential: await buildSdJwt(VCDM_CREDENTIAL) });

		expect(result.success).toBe(true);
		if (!result.success) return;
		expect(result.value.validityInfo.validFrom?.toISOString()).toBe("2026-01-01T00:00:00.000Z");
		expect(result.value.validityInfo.validUntil?.toISOString()).toBe("2027-01-01T00:00:00.000Z");
	});

	it("reads an issuer object with an id and a name", async () => {
		const raw = await buildSdJwt({
			...VCDM_CREDENTIAL,
			issuer: { id: "did:web:university.example", name: "Example University" },
		});

		const result = await parser().parse({ rawCredential: raw });

		expect(result.success).toBe(true);
		if (!result.success) return;
		expect(result.value.metadata.issuer).toEqual({
			id: "did:web:university.example",
			name: "Example University",
		});
	});

	it("declines an SD-JWT VC, which has a vct instead of an @context", async () => {
		const raw = await buildSdJwt({ vct: "urn:eudi:pid:1", iss: "https://issuer.example", given_name: "Alice" });

		const result = await parser().parse({ rawCredential: raw });

		expect(result.success).toBe(false);
		expect(!result.success && result.error).toBe(CredentialParsingError.UnsupportedFormat);
	});

	it("rejects a payload using the forbidden vc claim name", async () => {
		// VC-JOSE-COSE §3.2.1: "The JWT Claim Names `vc` and `vp` MUST NOT be present."
		const raw = await buildSdJwt({ ...VCDM_CREDENTIAL, vc: { some: "envelope" } });

		const result = await parser().parse({ rawCredential: raw });

		expect(result.success).toBe(false);
		expect(!result.success && result.error).toBe(CredentialParsingError.InvalidSdJwtVcPayload);
	});

	it("rejects a credential with no resolvable issuer", async () => {
		const { issuer, ...withoutIssuer } = VCDM_CREDENTIAL;
		const result = await parser().parse({ rawCredential: await buildSdJwt(withoutIssuer) });

		expect(result.success).toBe(false);
		expect(!result.success && result.error).toBe(CredentialParsingError.InvalidSdJwtVcPayload);
	});
});

describe("VCDM 2.0 / SD-JWT VC disambiguation", () => {
	it("detects a VCDM 2.0 credential despite the shared vc+sd-jwt typ", async () => {
		expect(detectCredentialFormat(await buildSdJwt(VCDM_CREDENTIAL)))
			.toBe(VerifiableCredentialFormat.W3C_VCDM_SDJWT);
	});

	it("still detects a vct-bearing payload as SD-JWT VC", async () => {
		const raw = await buildSdJwt({ vct: "urn:eudi:pid:1", iss: "https://issuer.example" });

		expect(detectCredentialFormat(raw)).toBe(VerifiableCredentialFormat.VC_SDJWT);
	});

	it("keeps SDJWTVCParser from claiming a VCDM payload", async () => {
		// Without this the ParsingEngine would stop at SDJWTVCParser's InvalidSdJwtVcPayload
		// and never reach VCDMSDJWTParser.
		const result = await SDJWTVCParser({ context, httpClient }).parse({
			rawCredential: await buildSdJwt(VCDM_CREDENTIAL),
		});

		expect(result.success).toBe(false);
		expect(!result.success && result.error).toBe(CredentialParsingError.UnsupportedFormat);
	});
});
