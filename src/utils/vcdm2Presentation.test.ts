import { describe, expect, it } from "vitest";
import {
	ENVELOPED_VC_MEDIA_TYPE,
	buildVcdm2Presentation,
	holderIdFromCredential,
	holderJwkFromCredential,
	wrapCredentialForPresentation,
} from "./vcdm2Presentation";

function b64url(value: object): string {
	const bytes = new TextEncoder().encode(JSON.stringify(value));
	let binary = "";
	for (const b of bytes) binary += String.fromCharCode(b);
	return btoa(binary).replace(/\+/g, "-").replace(/_/g, "_").replace(/\//g, "_").replace(/=+$/, "");
}

const holderJwk = { kty: "EC", crv: "P-256", x: "abc", y: "def" };

const ldpCredential = {
	"@context": ["https://www.w3.org/ns/credentials/v2"],
	type: ["VerifiableCredential"],
	issuer: "did:example:issuer",
	credentialSubject: { id: "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK", name: "Alice" },
};

function envelopedVc(payloadExtras: Record<string, unknown> = {}): string {
	const payload = {
		"@context": ["https://www.w3.org/ns/credentials/v2"],
		type: ["VerifiableCredential"],
		issuer: "did:example:issuer",
		credentialSubject: { id: "did:example:holder" },
		...payloadExtras,
	};
	return `${b64url({ alg: "ES256", typ: "vc+jwt" })}.${b64url(payload)}.sig`;
}

describe("wrapCredentialForPresentation", () => {
	it("wraps an enveloped credential as an EnvelopedVerifiableCredential data URI", () => {
		const raw = envelopedVc();
		const wrapped = wrapCredentialForPresentation(raw) as Record<string, unknown>;

		expect(wrapped.type).toBe("EnvelopedVerifiableCredential");
		expect(wrapped["@context"]).toBe("https://www.w3.org/ns/credentials/v2");
		expect(wrapped.id).toBe(`data:${ENVELOPED_VC_MEDIA_TYPE},${raw}`);
	});

	it("embeds a Data Integrity credential object directly", () => {
		expect(wrapCredentialForPresentation(ldpCredential)).toEqual(ldpCredential);
	});

	it("accepts a Data Integrity credential given as JSON text", () => {
		expect(wrapCredentialForPresentation(JSON.stringify(ldpCredential))).toEqual(ldpCredential);
	});

	it("rejects anything that is not a VCDM 2.0 credential", () => {
		expect(() => wrapCredentialForPresentation("not-a-credential")).toThrow(/not a VCDM 2.0 credential/);
		expect(() => wrapCredentialForPresentation({ foo: "bar" })).toThrow(/not a VCDM 2.0 credential/);
		expect(() => wrapCredentialForPresentation(null)).toThrow(/not a VCDM 2.0 credential/);
	});
});

describe("buildVcdm2Presentation", () => {
	it("builds a presentation around a single credential", () => {
		const presentation = buildVcdm2Presentation([ldpCredential]);

		expect(presentation["@context"]).toEqual(["https://www.w3.org/ns/credentials/v2"]);
		expect(presentation.type).toEqual(["VerifiablePresentation"]);
		expect(presentation.verifiableCredential).toEqual([ldpCredential]);
		expect(presentation.holder).toBeUndefined();
	});

	it("includes the holder when one is supplied", () => {
		const presentation = buildVcdm2Presentation([ldpCredential], { holder: "did:example:holder" });
		expect(presentation.holder).toBe("did:example:holder");
	});

	it("omits an empty holder rather than emitting a blank claim", () => {
		const presentation = buildVcdm2Presentation([ldpCredential], { holder: "" });
		expect(presentation.holder).toBeUndefined();
	});

	it("carries several credentials, mixing both securing mechanisms", () => {
		const presentation = buildVcdm2Presentation([envelopedVc(), ldpCredential]);
		expect(presentation.verifiableCredential).toHaveLength(2);
		expect((presentation.verifiableCredential[0] as any).type).toBe("EnvelopedVerifiableCredential");
		expect(presentation.verifiableCredential[1]).toEqual(ldpCredential);
	});

	it("refuses to build an empty presentation", () => {
		expect(() => buildVcdm2Presentation([])).toThrow(/at least one credential/);
	});
});

describe("holderJwkFromCredential", () => {
	it("reads cnf.jwk from an enveloped credential", () => {
		const raw = envelopedVc({ cnf: { jwk: holderJwk } });
		expect(holderJwkFromCredential(raw)).toEqual(holderJwk);
	});

	it("returns null when an enveloped credential has no cnf binding", () => {
		expect(holderJwkFromCredential(envelopedVc())).toBeNull();
	});

	it("returns null when cnf.jwk is not an object", () => {
		expect(holderJwkFromCredential(envelopedVc({ cnf: { jwk: "nope" } }))).toBeNull();
	});

	it("derives the key from a did:key subject on a Data Integrity credential", () => {
		const jwk = holderJwkFromCredential(ldpCredential);
		expect(jwk).not.toBeNull();
		expect(jwk?.kty).toBe("OKP");
		expect(jwk?.crv).toBe("Ed25519");
	});

	it("reads the first entry when credentialSubject is an array", () => {
		const jwk = holderJwkFromCredential({
			...ldpCredential,
			credentialSubject: [ldpCredential.credentialSubject, { id: "did:example:other" }],
		});
		expect(jwk?.crv).toBe("Ed25519");
	});

	it("returns null when the subject id is not a did:key", () => {
		expect(holderJwkFromCredential({
			...ldpCredential,
			credentialSubject: { id: "did:example:subject" },
		})).toBeNull();
	});

	it("returns null when the subject has no id at all", () => {
		expect(holderJwkFromCredential({ ...ldpCredential, credentialSubject: { name: "Alice" } })).toBeNull();
	});

	it("returns null for a malformed did:key rather than throwing", () => {
		expect(holderJwkFromCredential({
			...ldpCredential,
			credentialSubject: { id: "did:key:zNotValidBase58!!" },
		})).toBeNull();
	});

	it("returns null for anything that is not a VCDM 2.0 credential", () => {
		expect(holderJwkFromCredential("plain string")).toBeNull();
		expect(holderJwkFromCredential({ foo: 1 })).toBeNull();
	});
});

describe("holderIdFromCredential", () => {
	it("reads the subject id from an enveloped credential", () => {
		expect(holderIdFromCredential(envelopedVc())).toBe("did:example:holder");
	});

	it("reads the subject id from a Data Integrity credential", () => {
		expect(holderIdFromCredential(ldpCredential)).toBe(ldpCredential.credentialSubject.id);
	});

	it("reads the first entry when credentialSubject is an array", () => {
		expect(holderIdFromCredential({
			...ldpCredential,
			credentialSubject: [{ id: "did:example:first" }, { id: "did:example:second" }],
		})).toBe("did:example:first");
	});

	it("returns undefined when there is no subject id", () => {
		expect(holderIdFromCredential({ ...ldpCredential, credentialSubject: {} })).toBeUndefined();
	});

	it("returns undefined for input that is not a credential", () => {
		expect(holderIdFromCredential("nonsense")).toBeUndefined();
		expect(holderIdFromCredential(null)).toBeUndefined();
	});

	it("returns undefined when the subject id is not a string", () => {
		expect(holderIdFromCredential({ ...ldpCredential, credentialSubject: { id: 42 } })).toBeUndefined();
	});
});
