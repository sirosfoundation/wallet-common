import { VCDM2_CONTEXT_V2 } from "../schemas/Vcdm2CredentialSchema";
import {
	coerceCredentialObject,
	decodeCompactJws,
	isVcdm2Credential,
	looksLikeEnvelopedVcdm2,
} from "./vcdm2";
import { didKeyToJwk } from "./dataIntegrity/multibase";

/**
 * Building blocks for presenting W3C VCDM 2.0 credentials.
 *
 * A VCDM 2.0 presentation is itself a credential-shaped object that gets
 * secured; the wallet secures it with an enveloping JOSE proof, so these
 * helpers produce the *unsecured* presentation and identify which holder key
 * should sign it. Signing lives in the wallet's keystore, which is the only
 * component with access to private key material.
 */

/** Media type used in the `data:` URI of an enveloped verifiable credential. */
export const ENVELOPED_VC_MEDIA_TYPE = "application/vc+jwt";

/**
 * A public JWK, described structurally rather than as jose's `JWK`.
 *
 * Consumers may resolve a different major version of jose than this package
 * does — wallet-frontend pins ^4 while this package needs ^5 — and the two
 * `JWK` interfaces are then distinct types even though the values are
 * identical. A structural type crosses that boundary cleanly.
 */
export type HolderPublicJwk = {
	kty?: string;
	crv?: string;
	x?: string;
	y?: string;
	alg?: string;
	kid?: string;
	use?: string;
	d?: string;
	[propName: string]: unknown;
};

export type Vcdm2Presentation = {
	"@context": string[];
	type: string[];
	holder?: string;
	verifiableCredential: unknown[];
};

/**
 * Wrap a credential for inclusion in a VCDM 2.0 presentation.
 *
 * An enveloped (JWS) credential cannot be embedded as a JSON object, so
 * VCDM 2.0 represents it as an `EnvelopedVerifiableCredential` whose `id` is a
 * `data:` URI carrying the compact JWS. A Data Integrity credential is
 * already a JSON-LD object and is embedded directly.
 */
export function wrapCredentialForPresentation(rawCredential: unknown): unknown {
	if (looksLikeEnvelopedVcdm2(rawCredential)) {
		return {
			"@context": VCDM2_CONTEXT_V2,
			id: `data:${ENVELOPED_VC_MEDIA_TYPE},${rawCredential as string}`,
			type: "EnvelopedVerifiableCredential",
		};
	}

	const candidate = coerceCredentialObject(rawCredential);
	if (candidate !== null && isVcdm2Credential(candidate)) {
		return candidate;
	}

	throw new Error("Credential is not a VCDM 2.0 credential");
}

/**
 * Build an unsecured VCDM 2.0 verifiable presentation.
 *
 * `holder` is omitted when unknown rather than guessed: an incorrect holder
 * claim is worse than an absent one, since the verifier checks it against the
 * key that signs the envelope.
 */
export function buildVcdm2Presentation(
	rawCredentials: unknown[],
	options: { holder?: string } = {},
): Vcdm2Presentation {
	if (rawCredentials.length === 0) {
		throw new Error("A presentation must contain at least one credential");
	}

	const presentation: Vcdm2Presentation = {
		"@context": [VCDM2_CONTEXT_V2],
		type: ["VerifiablePresentation"],
		verifiableCredential: rawCredentials.map(wrapCredentialForPresentation),
	};

	if (options.holder) {
		presentation.holder = options.holder;
	}

	return presentation;
}

/**
 * Determine the public key the holder must prove possession of.
 *
 * Two bindings are recognised:
 *   - an enveloped credential's `cnf.jwk`, the same mechanism SD-JWT VC uses;
 *   - a Data Integrity credential whose `credentialSubject.id` is a `did:key`,
 *     which is the conventional binding for that format.
 *
 * Returns null when the credential carries no holder binding at all, which
 * the caller must treat as "cannot present" rather than picking a key.
 */
export function holderJwkFromCredential(rawCredential: unknown): HolderPublicJwk | null {
	if (looksLikeEnvelopedVcdm2(rawCredential)) {
		const decoded = decodeCompactJws(rawCredential);
		const jwk = decoded?.payload?.cnf?.jwk;
		return jwk && typeof jwk === "object" ? jwk as HolderPublicJwk : null;
	}

	const candidate = coerceCredentialObject(rawCredential);
	if (candidate === null || !isVcdm2Credential(candidate)) return null;

	const subject = (candidate as Record<string, unknown>).credentialSubject;
	const subjectId = Array.isArray(subject)
		? (subject[0] as Record<string, unknown> | undefined)?.id
		: (subject as Record<string, unknown> | undefined)?.id;

	if (typeof subjectId !== "string" || !subjectId.startsWith("did:key:")) return null;

	try {
		return didKeyToJwk(subjectId) as HolderPublicJwk;
	} catch {
		return null;
	}
}

/**
 * The holder identifier to place in the presentation, when the credential
 * names one. Mirrors `holderJwkFromCredential`'s sources.
 */
export function holderIdFromCredential(rawCredential: unknown): string | undefined {
	const candidate = looksLikeEnvelopedVcdm2(rawCredential)
		? decodeCompactJws(rawCredential)?.payload
		: coerceCredentialObject(rawCredential);

	if (candidate === null || typeof candidate !== "object") return undefined;

	const subject = (candidate as Record<string, unknown>).credentialSubject;
	const subjectId = Array.isArray(subject)
		? (subject[0] as Record<string, unknown> | undefined)?.id
		: (subject as Record<string, unknown> | undefined)?.id;

	return typeof subjectId === "string" ? subjectId : undefined;
}
