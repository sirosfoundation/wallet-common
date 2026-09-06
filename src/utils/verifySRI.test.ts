import { describe, it, expect } from "vitest";
import crypto from "crypto";
import { verifySRI } from "./verifySRIFromObject";

const subtle = crypto.webcrypto.subtle as SubtleCrypto;

function sri(content: string, algorithm: "sha256" | "sha384" | "sha512" = "sha256"): string {
	return `${algorithm}-${crypto.createHash(algorithm).update(content, "utf8").digest("base64")}`;
}

/**
 * SRI is defined over the octets of the resource as served.
 *
 * The case that matters is a pretty-printed document: hashing a re-serialised
 * parse of it produces a digest that cannot match the one its issuer published,
 * so correct metadata is reported as tampered with.
 */
describe("verifySRI", () => {
	const served = `{\n  "vct": "urn:eudi:pid:1",\n  "name": "PID"\n}`;

	it("matches a digest over the bytes as served", async () => {
		expect(await verifySRI(subtle, served, sri(served))).toBe(true);
	});

	it("matches a pretty-printed document that a parsed object cannot", async () => {
		// The regression this file exists for. The issuer hashed what it
		// serves; the wallet used to hash JSON.stringify(JSON.parse(...)),
		// which drops the whitespace and yields a different digest.
		const expected = sri(served);
		expect(await verifySRI(subtle, served, expected)).toBe(true);
		expect(await verifySRI(subtle, JSON.parse(served), expected)).toBe(false);
	});

	it("still hashes an object when no raw body is available", async () => {
		// The documented fallback: correct whenever the document was served
		// compact, which is why this went unnoticed.
		const compact = `{"vct":"urn:eudi:pid:1"}`;
		expect(await verifySRI(subtle, JSON.parse(compact), sri(compact))).toBe(true);
	});

	it("rejects a digest of different content", async () => {
		expect(await verifySRI(subtle, served, sri("something else"))).toBe(false);
	});

	it("supports sha384 and sha512", async () => {
		expect(await verifySRI(subtle, served, sri(served, "sha384"))).toBe(true);
		expect(await verifySRI(subtle, served, sri(served, "sha512"))).toBe(true);
	});

	it("accepts any of several space-separated digests", async () => {
		// SRI permits a list, strongest first; any one matching is a match.
		expect(await verifySRI(subtle, served, `sha512-AAAA ${sri(served)}`)).toBe(true);
	});

	it("does not truncate a digest spelled in the URL-safe alphabet", async () => {
		// base64url contains dashes. Splitting on every dash cut the digest
		// short and guaranteed a mismatch.
		const urlSafe = crypto.createHash("sha256").update(served, "utf8").digest("base64url");
		expect(urlSafe).toMatch(/[-_]|.*/);
		expect(await verifySRI(subtle, served, `sha256-${urlSafe}`)).toBe(true);
	});

	it("returns false rather than throwing on a malformed value", async () => {
		// "could not check" is not "checked and passed", and a throw would
		// escape past callers that only handle a false result.
		expect(await verifySRI(subtle, served, "")).toBe(false);
		expect(await verifySRI(subtle, served, "sha256")).toBe(false);
		expect(await verifySRI(subtle, served, "-abc")).toBe(false);
		expect(await verifySRI(subtle, served, "md5-abc")).toBe(false);
		expect(await verifySRI(subtle, served, "sha256-not!base64")).toBe(false);
	});
});
