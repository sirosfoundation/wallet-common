import { z } from "zod";

/**
 * W3C Verifiable Credentials Data Model 2.0.
 *
 * Shared by both securing mechanisms:
 *   - an enveloping JOSE proof (VC-JOSE-COSE), where the JWT payload *is* the
 *     credential object, and
 *   - an embedded Data Integrity proof, where the credential is a JSON-LD
 *     object carrying its own `proof` member.
 *
 * Deliberately permissive beyond the few members VCDM 2.0 actually mandates:
 * the wallet's job is to display credentials others issue, so unknown members
 * are carried through rather than rejected.
 */

export const VCDM2_CONTEXT_V2 = "https://www.w3.org/ns/credentials/v2";

/** `issuer` is either a URI string or an object with an `id`. (VCDM 2.0 §4.6) */
export const Vcdm2IssuerSchema = z.union([
	z.string().min(1),
	z.object({ id: z.string().min(1) }).passthrough(),
]);

/**
 * A Data Integrity proof. `type` is always "DataIntegrityProof" for the
 * cryptosuites we care about, but the older `Ed25519Signature2020`-style
 * types put the suite in `type` itself, so neither is constrained here.
 */
export const DataIntegrityProofSchema = z.object({
	type: z.string().min(1),
	cryptosuite: z.string().min(1).optional(),
	created: z.string().optional(),
	expires: z.string().optional(),
	verificationMethod: z.string().min(1),
	proofPurpose: z.string().min(1),
	proofValue: z.string().min(1).optional(),
	domain: z.union([z.string(), z.array(z.string())]).optional(),
	challenge: z.string().optional(),
	previousProof: z.union([z.string(), z.array(z.string())]).optional(),
}).passthrough();

export const Vcdm2CredentialStatusSchema = z.object({
	id: z.string().optional(),
	type: z.union([z.string(), z.array(z.string())]),
}).passthrough();

/**
 * The credential object itself.
 *
 * `@context` MUST be an ordered set whose first value is the VCDM 2.0 context
 * (VCDM 2.0 §4.1); that ordering is enforced by `isVcdm2Credential` rather
 * than here, so that a context-less object still parses far enough to produce
 * a useful error.
 */
export const Vcdm2CredentialSchema = z.object({
	"@context": z.array(z.union([z.string(), z.record(z.any())])).min(1),
	id: z.string().optional(),
	type: z.union([z.string(), z.array(z.string())]),
	issuer: Vcdm2IssuerSchema,
	name: z.union([z.string(), z.array(z.any())]).optional(),
	description: z.union([z.string(), z.array(z.any())]).optional(),
	// VCDM 2.0 replaced 1.1's issuanceDate/expirationDate with these.
	validFrom: z.string().optional(),
	validUntil: z.string().optional(),
	credentialSubject: z.union([
		z.record(z.any()),
		z.array(z.record(z.any())),
	]),
	credentialStatus: z.union([
		Vcdm2CredentialStatusSchema,
		z.array(Vcdm2CredentialStatusSchema),
	]).optional(),
	credentialSchema: z.union([z.record(z.any()), z.array(z.record(z.any()))]).optional(),
	termsOfUse: z.union([z.record(z.any()), z.array(z.record(z.any()))]).optional(),
	evidence: z.union([z.record(z.any()), z.array(z.record(z.any()))]).optional(),
	proof: z.union([
		DataIntegrityProofSchema,
		z.array(DataIntegrityProofSchema),
	]).optional(),
}).passthrough();

/** Header of a VCDM 2.0 credential secured with an enveloping JOSE proof. */
export const Vcdm2JoseHeaderSchema = z.object({
	alg: z.string().min(1),
	typ: z.string().optional(),
	cty: z.string().optional(),
	kid: z.string().optional(),
	x5c: z.array(z.string()).optional(),
	jwk: z.record(z.any()).optional(),
}).passthrough();

export type Vcdm2Credential = z.infer<typeof Vcdm2CredentialSchema>;
export type Vcdm2Issuer = z.infer<typeof Vcdm2IssuerSchema>;
export type Vcdm2JoseHeader = z.infer<typeof Vcdm2JoseHeaderSchema>;
export type DataIntegrityProof = z.infer<typeof DataIntegrityProofSchema>;
