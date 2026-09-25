import { describe, expect, it } from "vitest";
import { base58Decode, multibaseDecode, multikeyToJwk, didKeyToJwk } from "./multibase";
import { canonicalizeJcs } from "./jcs";
import { verifyDataIntegrityProof } from "./verifyDataIntegrityProof";
import type { HttpClient } from "../../interfaces";

const subtle = globalThis.crypto.subtle;

/** An HttpClient that fails loudly: the JCS suites must never need the network. */
const forbiddenHttpClient: HttpClient = {
	async get() { throw new Error("network access is not expected for JCS cryptosuites"); },
	async post() { throw new Error("network access is not expected for JCS cryptosuites"); },
};

function base64UrlEncode(bytes: Uint8Array): string {
	let binary = "";
	for (const b of bytes) binary += String.fromCharCode(b);
	return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64UrlDecode(value: string): Uint8Array {
	const padded = value + "=".repeat((4 - (value.length % 4)) % 4);
	const binary = atob(padded.replace(/-/g, "+").replace(/_/g, "/"));
	return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

describe("base58Decode", () => {
	it("decodes the Bitcoin base58 test vectors", () => {
		expect(Array.from(base58Decode("2NEpo7TZRRrLZSi2U"))).toEqual(
			Array.from(new TextEncoder().encode("Hello World!")),
		);
		expect(base58Decode("").length).toBe(0);
	});

	it("decodes leading '1' characters as leading zero bytes", () => {
		expect(Array.from(base58Decode("1112"))).toEqual([0, 0, 0, 1]);
	});

	it("rejects characters outside the alphabet", () => {
		// '0', 'O', 'I' and 'l' are excluded from the base58btc alphabet.
		expect(() => base58Decode("0OIl")).toThrow();
	});
});

describe("multibaseDecode", () => {
	it("supports base58btc ('z') and base64url ('u')", () => {
		const bytes = new Uint8Array([1, 2, 3, 250]);
		expect(Array.from(multibaseDecode("u" + base64UrlEncode(bytes)))).toEqual([1, 2, 3, 250]);
		expect(Array.from(multibaseDecode("z2NEpo7TZRRrLZSi2U"))).toEqual(
			Array.from(new TextEncoder().encode("Hello World!")),
		);
	});

	it("rejects an unsupported multibase prefix", () => {
		expect(() => multibaseDecode("f00ff")).toThrow(/unsupported prefix/);
	});
});

describe("multikeyToJwk", () => {
	it("decodes an Ed25519 multikey", () => {
		const raw = new Uint8Array(32).fill(7);
		const multikey = new Uint8Array([0xed, 0x01, ...raw]);
		const jwk = multikeyToJwk(multikey);
		expect(jwk.kty).toBe("OKP");
		expect(jwk.crv).toBe("Ed25519");
		expect(base64UrlDecode(jwk.x as string)).toEqual(raw);
	});

	it("recovers x and y from a compressed P-256 point", async () => {
		// Generating a real key is the only honest way to test point
		// decompression — a hand-written vector would just encode my own
		// arithmetic back at me.
		const keyPair = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
		const jwk = await subtle.exportKey("jwk", keyPair.publicKey);

		const x = base64UrlDecode(jwk.x as string);
		const y = base64UrlDecode(jwk.y as string);
		const compressed = new Uint8Array([(y[y.length - 1] & 1) === 1 ? 0x03 : 0x02, ...x]);
		const multikey = new Uint8Array([0x80, 0x24, ...compressed]);

		const decoded = multikeyToJwk(multikey);
		expect(decoded.kty).toBe("EC");
		expect(decoded.crv).toBe("P-256");
		expect(decoded.x).toBe(jwk.x);
		expect(decoded.y).toBe(jwk.y);
	});

	it("accepts an uncompressed point as well", async () => {
		const keyPair = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
		const jwk = await subtle.exportKey("jwk", keyPair.publicKey);
		const x = base64UrlDecode(jwk.x as string);
		const y = base64UrlDecode(jwk.y as string);
		const multikey = new Uint8Array([0x80, 0x24, 0x04, ...x, ...y]);

		const decoded = multikeyToJwk(multikey);
		expect(decoded.x).toBe(jwk.x);
		expect(decoded.y).toBe(jwk.y);
	});

	it("rejects an unknown multicodec prefix", () => {
		expect(() => multikeyToJwk(new Uint8Array([0x99, 0x99, 1, 2, 3]))).toThrow(/unsupported key type/);
	});
});

describe("didKeyToJwk", () => {
	it("resolves a did:key identifier, ignoring any fragment", () => {
		const raw = new Uint8Array(32).fill(3);
		const multikey = new Uint8Array([0xed, 0x01, ...raw]);
		const did = `did:key:u${base64UrlEncode(multikey)}`;

		const withoutFragment = didKeyToJwk(did);
		const withFragment = didKeyToJwk(`${did}#key-1`);
		expect(withoutFragment).toEqual(withFragment);
		expect(withoutFragment.crv).toBe("Ed25519");
	});
});

/**
 * End-to-end exercise of the Data Integrity pipeline using ecdsa-jcs-2019,
 * which needs no JSON-LD context resolution — so this asserts the
 * canonicalize/hash/concatenate/verify sequence itself rather than jsonld's
 * behaviour.
 */
describe("verifyDataIntegrityProof (ecdsa-jcs-2019)", () => {
	const credentialBase = {
		"@context": ["https://www.w3.org/ns/credentials/v2"],
		id: "urn:uuid:0b1f3a4e-1f0a-4c9e-9a1e-2f4f6b1c2d3e",
		type: ["VerifiableCredential", "ExampleCredential"],
		issuer: "did:example:issuer",
		validFrom: "2026-01-01T00:00:00Z",
		credentialSubject: { id: "did:example:subject", name: "Alice" },
	};

	async function signCredential(overrides: { tamperAfterSigning?: boolean } = {}) {
		const keyPair = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
		const publicKey = await subtle.exportKey("jwk", keyPair.publicKey);

		const proofConfig = {
			type: "DataIntegrityProof",
			cryptosuite: "ecdsa-jcs-2019",
			created: "2026-01-01T00:00:00Z",
			verificationMethod: "did:example:issuer#key-1",
			proofPurpose: "assertionMethod",
		};

		const encoder = new TextEncoder();
		const proofConfigHash = new Uint8Array(await subtle.digest(
			"SHA-256",
			encoder.encode(canonicalizeJcs({ ...proofConfig, "@context": credentialBase["@context"] })),
		));
		const documentHash = new Uint8Array(await subtle.digest(
			"SHA-256",
			encoder.encode(canonicalizeJcs(credentialBase)),
		));

		const verifyData = new Uint8Array(proofConfigHash.length + documentHash.length);
		verifyData.set(proofConfigHash, 0);
		verifyData.set(documentHash, proofConfigHash.length);

		const signature = new Uint8Array(await subtle.sign(
			{ name: "ECDSA", hash: { name: "SHA-256" } },
			keyPair.privateKey,
			verifyData.buffer as ArrayBuffer,
		));

		const credential: any = {
			...credentialBase,
			proof: { ...proofConfig, proofValue: `u${base64UrlEncode(signature)}` },
		};

		if (overrides.tamperAfterSigning) {
			credential.credentialSubject = { ...credential.credentialSubject, name: "Mallory" };
		}

		return { credential, publicKey };
	}

	it("verifies a correctly signed credential", async () => {
		const { credential, publicKey } = await signCredential();

		const result = await verifyDataIntegrityProof({
			credential,
			proof: credential.proof,
			publicKey,
			subtle,
			httpClient: forbiddenHttpClient,
		});

		expect(result.success).toBe(true);
	});

	it("rejects a credential modified after signing", async () => {
		const { credential, publicKey } = await signCredential({ tamperAfterSigning: true });

		const result = await verifyDataIntegrityProof({
			credential,
			proof: credential.proof,
			publicKey,
			subtle,
			httpClient: forbiddenHttpClient,
		});

		expect(result.success).toBe(false);
		if (!result.success) expect(result.failure.kind).toBe("invalid-signature");
	});

	it("rejects a proof whose configuration was altered after signing", async () => {
		const { credential, publicKey } = await signCredential();
		// Same signature, different proof purpose: the proof config is part
		// of the signed data, so this must not verify.
		const proof = { ...credential.proof, proofPurpose: "authentication" };

		const result = await verifyDataIntegrityProof({
			credential,
			proof,
			publicKey,
			subtle,
			httpClient: forbiddenHttpClient,
		});

		expect(result.success).toBe(false);
	});

	it("reports an unsupported cryptosuite rather than failing the signature", async () => {
		const { credential, publicKey } = await signCredential();
		const proof = { ...credential.proof, cryptosuite: "ecdsa-sd-2023" };

		const result = await verifyDataIntegrityProof({
			credential,
			proof,
			publicKey,
			subtle,
			httpClient: forbiddenHttpClient,
		});

		expect(result.success).toBe(false);
		if (!result.success) {
			expect(result.failure.kind).toBe("unsupported-cryptosuite");
		}
	});

	it("reports a missing proofValue as an invalid proof", async () => {
		const { credential, publicKey } = await signCredential();
		const { proofValue: _omitted, ...proof } = credential.proof;

		const result = await verifyDataIntegrityProof({
			credential,
			proof: proof as any,
			publicKey,
			subtle,
			httpClient: forbiddenHttpClient,
		});

		expect(result.success).toBe(false);
		if (!result.success) expect(result.failure.kind).toBe("invalid-proof");
	});
});
