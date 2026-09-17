/**
 * DID resolution for the DID methods required by the DIIP profile: did:jwk and did:web.
 *
 * DIIP v5 requires implementations to support did:jwk and did:web as the identifiers of
 * Issuers, Holders and Verifiers. did:jwk resolves offline (the key is encoded in the
 * identifier); did:web requires an HTTPS fetch of the DID document.
 *
 * @see https://github.com/quartzjer/did-jwk/blob/main/spec.md
 * @see https://w3c-ccg.github.io/did-method-web/
 */

import { JWK } from "jose";
import { PublicKeyResolutionError } from "../error";
import { HttpClient, PublicKeyResolver } from "../interfaces";
import {
	DIDDocument,
	DIDResolutionResult,
	DIDResolver,
	DIDVerificationMethod,
} from "../protocols/openid4vp/types";
import { fromBase64Url } from "../utils/util";

const textDecoder = new TextDecoder();

/**
 * Verification method relationships DIIP refers to. `assertionMethod` is used for
 * issuer/verifier signatures, `authentication` for holder key binding.
 */
export type VerificationRelationship = "assertionMethod" | "authentication";

/**
 * Resolve a `did:jwk` identifier. The JWK is base64url-encoded in the identifier itself,
 * so this never touches the network.
 *
 * The resulting document exposes a single verification method `<did>#0`, which — per the
 * did:jwk spec — appears in every relationship unless the key's `use` restricts it.
 */
export function resolveDidJwk(did: string): DIDResolutionResult {
	if (!did.startsWith("did:jwk:")) {
		return { resolved: false, error: `Not a did:jwk identifier: ${did}` };
	}

	// A DID URL may carry a fragment/query; the method-specific id is everything before it.
	const methodSpecificId = did.slice("did:jwk:".length).split(/[#?]/)[0];
	if (!methodSpecificId) {
		return { resolved: false, error: "did:jwk identifier has an empty method-specific id" };
	}

	let jwk: JWK;
	try {
		jwk = JSON.parse(textDecoder.decode(fromBase64Url(methodSpecificId)));
	}
	catch (err) {
		return { resolved: false, error: `Could not decode the JWK in ${did}: ${err}` };
	}

	if (typeof jwk !== "object" || jwk === null || typeof jwk.kty !== "string") {
		return { resolved: false, error: `did:jwk does not encode a valid JWK: ${did}` };
	}
	if ("d" in jwk) {
		// A did:jwk must never encode private key material.
		return { resolved: false, error: "did:jwk encodes a private key" };
	}

	const didWithoutFragment = `did:jwk:${methodSpecificId}`;
	const verificationMethod: DIDVerificationMethod = {
		id: `${didWithoutFragment}#0`,
		type: "JsonWebKey2020",
		controller: didWithoutFragment,
		publicKeyJwk: jwk as JsonWebKey,
	};

	// Per the did:jwk spec the key is usable for every relationship unless `use` narrows it.
	// `use: "enc"` keys are keyAgreement-only, so they take part in neither relationship we model.
	const signingCapable = jwk.use !== "enc";

	return {
		resolved: true,
		didDocument: {
			id: didWithoutFragment,
			verificationMethod: [verificationMethod],
			assertionMethod: signingCapable ? [verificationMethod.id] : [],
			authentication: signingCapable ? [verificationMethod.id] : [],
		},
	};
}

/**
 * Translate a `did:web` identifier into the URL of its DID document.
 *
 * `did:web:example.com` -> `https://example.com/.well-known/did.json`
 * `did:web:example.com:org:1` -> `https://example.com/org/1/did.json`
 * A percent-encoded colon in the host segment carries the port.
 */
export function didWebToUrl(did: string): string | null {
	if (!did.startsWith("did:web:")) {
		return null;
	}
	const methodSpecificId = did.slice("did:web:".length).split(/[#?]/)[0];
	if (!methodSpecificId) {
		return null;
	}

	const segments = methodSpecificId.split(":").map((s) => decodeURIComponent(s));
	const [host, ...path] = segments;
	if (!host) {
		return null;
	}

	return path.length === 0
		? `https://${host}/.well-known/did.json`
		: `https://${host}/${path.join("/")}/did.json`;
}

/**
 * Resolve a `did:web` identifier by fetching its DID document.
 */
export async function resolveDidWeb(did: string, httpClient: HttpClient): Promise<DIDResolutionResult> {
	const url = didWebToUrl(did);
	if (!url) {
		return { resolved: false, error: `Not a did:web identifier: ${did}` };
	}

	try {
		const response = await httpClient.get(url, {}, { useCache: true });
		if (response.status !== 200 || !response.data || typeof response.data !== "object") {
			return { resolved: false, error: `did:web document at ${url} returned status ${response.status}` };
		}
		const didDocument = response.data as DIDDocument;
		if (typeof didDocument.id !== "string") {
			return { resolved: false, error: `did:web document at ${url} has no "id"` };
		}
		return { resolved: true, didDocument };
	}
	catch (err) {
		return { resolved: false, error: `Could not fetch the did:web document at ${url}: ${err}` };
	}
}

/**
 * Build a {@link DIDResolver} covering the DID methods DIIP requires.
 *
 * `did:web` needs an HTTP client; when none is supplied only `did:jwk` resolves.
 */
export function createDidResolver(args: { httpClient?: HttpClient } = {}): DIDResolver {
	return async (did: string): Promise<DIDResolutionResult> => {
		if (did.startsWith("did:jwk:")) {
			return resolveDidJwk(did);
		}
		if (did.startsWith("did:web:")) {
			if (!args.httpClient) {
				return { resolved: false, error: "did:web resolution requires an HTTP client" };
			}
			return resolveDidWeb(did, args.httpClient);
		}
		return { resolved: false, error: `Unsupported DID method: ${did}` };
	};
}

/**
 * Look up a public key in a DID document.
 *
 * When `didUrl` carries a fragment, only that verification method matches. When it does not,
 * the first verification method in the requested relationship is returned — DIIP requires
 * `assertionMethod` for issuer signatures and `authentication` for holder binding.
 */
export function findPublicKeyInDidDocument(
	didDocument: DIDDocument,
	didUrl: string,
	relationship: VerificationRelationship,
): JWK | null {
	const verificationMethods = didDocument.verificationMethod ?? [];

	const dereference = (entry: string | DIDVerificationMethod): DIDVerificationMethod | undefined =>
		typeof entry === "string"
			? verificationMethods.find((vm) => vm.id === entry || vm.id.endsWith(entry))
			: entry;

	const fragmentIndex = didUrl.indexOf("#");
	if (fragmentIndex !== -1) {
		// An absolute or relative DID URL identifying one specific verification method.
		const absolute = didUrl.startsWith("#") ? `${didDocument.id}${didUrl}` : didUrl;
		const match = verificationMethods.find((vm) => vm.id === absolute)
			?? (didDocument[relationship] ?? []).map(dereference).find((vm) => vm?.id === absolute);
		return (match?.publicKeyJwk as JWK) ?? null;
	}

	const first = (didDocument[relationship] ?? []).map(dereference).find((vm) => vm?.publicKeyJwk);
	return (first?.publicKeyJwk as JWK) ?? null;
}

/**
 * A {@link PublicKeyResolver} for issuers identified by a DID, for registration on the
 * {@link PublicKeyResolverEngine}. Credentials whose `iss` is a did:jwk or did:web resolve
 * their signing key from the DID document's `assertionMethod` relationship, as DIIP requires.
 *
 * Identifiers that are not DIDs are declined so other resolvers get their turn.
 */
export function DidPublicKeyResolver(args: { httpClient?: HttpClient } = {}): PublicKeyResolver {
	const resolveDid = createDidResolver(args);

	return {
		async resolve({ identifier, kid }) {
			if (!identifier?.startsWith("did:")) {
				return { success: false, error: PublicKeyResolutionError.CannotResolvePublicKey };
			}

			const resolution = await resolveDid(identifier);
			if (!resolution.resolved || !resolution.didDocument) {
				return { success: false, error: PublicKeyResolutionError.CannotResolvePublicKey };
			}

			const jwk = findPublicKeyInDidDocument(resolution.didDocument, kid ?? identifier, "assertionMethod");
			if (!jwk) {
				return { success: false, error: PublicKeyResolutionError.CannotResolvePublicKey };
			}
			return { success: true, value: { jwk } };
		},
	};
}
