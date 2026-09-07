import {
	VCDM2_CONTEXT_V2,
	Vcdm2Credential,
	Vcdm2CredentialSchema,
	Vcdm2Issuer,
	DataIntegrityProof,
} from "../schemas/Vcdm2CredentialSchema";
import { fromBase64Url } from "./util";

/**
 * Shared helpers for W3C VCDM 2.0, used by both the JOSE (enveloping proof)
 * and Data Integrity (embedded proof) parsers and verifiers.
 */

const decoder = new TextDecoder();

/** `typ` values that identify an enveloped VCDM 2.0 credential. */
const VCDM2_JOSE_TYPES = new Set(["vc+jwt", "vc-ld+jwt", "vc+ld+jwt"]);

/**
 * True when `value` is shaped like a VCDM 2.0 credential.
 *
 * The VCDM 2.0 context being *first* is what actually separates a 2.0
 * credential from a 1.1 one (VCDM 2.0 §4.1); 1.1 credentials lead with
 * `https://www.w3.org/2018/credentials/v1`.
 */
export function isVcdm2Credential(value: unknown): value is Vcdm2Credential {
	if (typeof value !== "object" || value === null || Array.isArray(value)) return false;

	const ctx = (value as Record<string, unknown>)["@context"];
	if (!Array.isArray(ctx) || ctx.length === 0) return false;
	if (ctx[0] !== VCDM2_CONTEXT_V2) return false;

	// A credential must at least say what it is and who issued it.
	const record = value as Record<string, unknown>;
	if (record.type === undefined || record.issuer === undefined) return false;

	return true;
}

/**
 * True when the JWT header identifies an enveloped VCDM 2.0 credential.
 *
 * Some issuers omit `typ` entirely, so a payload-shape check is still needed
 * as a fallback — see `looksLikeEnvelopedVcdm2`.
 */
export function isVcdm2JoseHeaderType(typ: unknown): boolean {
	return typeof typ === "string" && VCDM2_JOSE_TYPES.has(typ.toLowerCase());
}

/**
 * Decode a compact JWS without verifying it.
 * Returns null when `raw` is not a well-formed three-part compact JWS.
 */
export function decodeCompactJws(raw: unknown): { header: any; payload: any } | null {
	if (typeof raw !== "string") return null;
	if (raw.includes("~")) return null; // SD-JWT, not ours

	const parts = raw.split(".");
	if (parts.length !== 3) return null;

	try {
		return {
			header: JSON.parse(decoder.decode(fromBase64Url(parts[0]))),
			payload: JSON.parse(decoder.decode(fromBase64Url(parts[1]))),
		};
	} catch {
		return null;
	}
}

/**
 * Decode a compact JWS if — and only if — it carries a VCDM 2.0 credential.
 *
 * Accepts either an explicit `typ` (the normal case) or, for issuers that
 * omit it, a payload that is itself a VCDM 2.0 credential. The payload check
 * is what keeps this from colliding with JWT_VC_JSON, whose credential sits
 * under a `vc` claim rather than at the top level.
 *
 * Callers get the decoded value back so they need not decode a second time,
 * which would leave them with an unreachable "failed to decode" branch.
 */
export function decodeEnvelopedVcdm2(raw: unknown): { header: any; payload: any } | null {
	const decoded = decodeCompactJws(raw);
	if (!decoded) return null;

	if (isVcdm2JoseHeaderType(decoded.header?.typ)) return decoded;

	// No/unknown `typ`: fall back to the payload shape, but never claim
	// something that is really a VCDM 1.1 `vc`-wrapped credential.
	if (decoded.payload && typeof decoded.payload === "object" && "vc" in decoded.payload) {
		return null;
	}
	return isVcdm2Credential(decoded.payload) ? decoded : null;
}

/** True when a compact JWS carries a VCDM 2.0 credential as its payload. */
export function looksLikeEnvelopedVcdm2(raw: unknown): raw is string {
	return decodeEnvelopedVcdm2(raw) !== null;
}

/** Parse and validate a credential object against the VCDM 2.0 schema. */
export function parseVcdm2Credential(value: unknown):
	{ success: true; value: Vcdm2Credential } | { success: false } {
	const result = Vcdm2CredentialSchema.safeParse(value);
	if (!result.success) return { success: false };
	return { success: true, value: result.data };
}

/** Normalise `type` (string | string[]) to an array. */
export function toTypeArray(type: unknown): string[] {
	if (typeof type === "string") return [type];
	if (Array.isArray(type)) return type.filter((t): t is string => typeof t === "string");
	return [];
}

/**
 * The credential type that is worth showing a user: the most specific entry,
 * i.e. the first that isn't the generic `VerifiableCredential`.
 */
export function primaryCredentialType(type: unknown): string | undefined {
	return toTypeArray(type).find((t) => t !== "VerifiableCredential");
}

/**
 * Resolve the identifier of a schema-validated issuer.
 *
 * `Vcdm2IssuerSchema` guarantees a string or an object with an `id`, so this
 * always yields a string — unlike `issuerIdentifier`, which accepts unknown
 * input and may return undefined.
 */
export function validatedIssuerIdentifier(issuer: Vcdm2Issuer): string {
	return typeof issuer === "string" ? issuer : issuer.id;
}

/** Human-readable name of a schema-validated issuer, else its identifier. */
export function validatedIssuerDisplayName(issuer: Vcdm2Issuer): string {
	// issuerDisplayName already falls back to the identifier, which a
	// schema-validated issuer always has, so the ?? arm cannot be reached.
	/* v8 ignore next -- unreachable for a schema-validated issuer */
	return issuerDisplayName(issuer) ?? validatedIssuerIdentifier(issuer);
}

/** Resolve `issuer` (string | { id }) to its identifier. */
export function issuerIdentifier(issuer: unknown): string | undefined {
	if (typeof issuer === "string") return issuer;
	if (issuer && typeof issuer === "object" && typeof (issuer as any).id === "string") {
		return (issuer as any).id;
	}
	return undefined;
}

/** Resolve a human-readable issuer name, falling back to its identifier. */
export function issuerDisplayName(issuer: unknown): string | undefined {
	if (issuer && typeof issuer === "object") {
		const name = (issuer as any).name;
		if (typeof name === "string") return name;
		// `name` may be a language map or an array of language objects.
		if (Array.isArray(name)) {
			const first = name.find((n) => typeof n?.["@value"] === "string" || typeof n?.value === "string");
			if (first) return first["@value"] ?? first.value;
		}
	}
	return issuerIdentifier(issuer);
}

/**
 * VCDM 2.0 validity, which uses XMLSchema dateTime strings rather than the
 * numeric `nbf`/`exp` a JWT carries.
 *
 * When a credential is enveloped in a JWT, the JWT's own registered claims
 * take precedence where present, since those are what a JWT verifier enforces.
 */
export function extractVcdm2ValidityInfo(
	credential: Vcdm2Credential,
	jwtClaims?: { exp?: number; iat?: number; nbf?: number },
): { validFrom?: Date; validUntil?: Date; signed?: Date } {
	const result: { validFrom?: Date; validUntil?: Date; signed?: Date } = {};

	const fromIso = (value: unknown): Date | undefined => {
		if (typeof value !== "string") return undefined;
		const date = new Date(value);
		return Number.isNaN(date.getTime()) ? undefined : date;
	};

	const validFrom = fromIso(credential.validFrom);
	if (validFrom) result.validFrom = validFrom;

	const validUntil = fromIso(credential.validUntil);
	if (validUntil) result.validUntil = validUntil;

	if (jwtClaims?.nbf) result.validFrom = new Date(jwtClaims.nbf * 1000);
	if (jwtClaims?.exp) result.validUntil = new Date(jwtClaims.exp * 1000);
	if (jwtClaims?.iat) result.signed = new Date(jwtClaims.iat * 1000);

	return result;
}

/** All Data Integrity proofs on a credential, normalised to an array. */
export function proofsOf(credential: Vcdm2Credential): DataIntegrityProof[] {
	const proof = credential.proof;
	if (!proof) return [];
	return Array.isArray(proof) ? proof : [proof];
}

/**
 * Accept a Data Integrity credential given either as an object or as its JSON
 * serialisation, since credentials arrive from storage as strings.
 */
export function coerceCredentialObject(raw: unknown): unknown | null {
	if (typeof raw === "object" && raw !== null && !Array.isArray(raw)) return raw;
	if (typeof raw !== "string") return null;

	const trimmed = raw.trim();
	if (!trimmed.startsWith("{")) return null;
	try {
		return JSON.parse(trimmed);
	} catch {
		return null;
	}
}
