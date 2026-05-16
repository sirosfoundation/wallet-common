import { z } from "zod";
import { OpenidCredentialIssuerMetadataSchema } from "../schemas";
import type { HttpClient } from "../interfaces";
import { MetadataWarning } from "../types";
import { CredentialParsingError } from "../error";
import type { IAuthZENClient } from "../authzen/AuthZENClient";

export async function getIssuerMetadata(
	httpClient: HttpClient,
	issuer: string,
	warnings: MetadataWarning[],
	useCache: boolean = true,
	authzenClient?: IAuthZENClient,
): Promise<{
	metadata: z.infer<typeof OpenidCredentialIssuerMetadataSchema> | null;
}> {
	if (!issuer) return { metadata: null };

	if (authzenClient) {
		return getIssuerMetadataViaResolve(authzenClient, issuer, warnings);
	}

	const url = `${issuer}/.well-known/openid-credential-issuer`;

	let issuerResponse = null;

	try {
		issuerResponse = await httpClient.get(url, {"Accept": "application/json"}, { useCache });
	} catch (err) {
		warnings.push({
			code: CredentialParsingError.FailFetchIssuerMetadata,
		});
		return { metadata: null };
	}

	if (!issuerResponse || issuerResponse.status !== 200 || !issuerResponse.data) {
		warnings.push({
			code: CredentialParsingError.FailFetchIssuerMetadata,
		});
		return { metadata: null };
	}

	const parsed = OpenidCredentialIssuerMetadataSchema.safeParse(issuerResponse.data);

	if (!parsed.success) {
		warnings.push({
			code: CredentialParsingError.FailSchemaIssuerMetadata,
		});
		return { metadata: null };
	}

	return { metadata: parsed.data };
}

async function getIssuerMetadataViaResolve(
	authzenClient: IAuthZENClient,
	issuer: string,
	warnings: MetadataWarning[],
): Promise<{
	metadata: z.infer<typeof OpenidCredentialIssuerMetadataSchema> | null;
}> {
	try {
		const result = await authzenClient.resolve(issuer, { resourceType: 'openid-credential-issuer' });
		if (!result.ok) {
			warnings.push({ code: CredentialParsingError.FailFetchIssuerMetadata });
			return { metadata: null };
		}

		const trustMetadata = result.value.context?.trust_metadata;
		if (!trustMetadata) {
			warnings.push({ code: CredentialParsingError.FailFetchIssuerMetadata });
			return { metadata: null };
		}

		const parsed = OpenidCredentialIssuerMetadataSchema.safeParse(trustMetadata);
		if (!parsed.success) {
			warnings.push({ code: CredentialParsingError.FailSchemaIssuerMetadata });
			return { metadata: null };
		}

		return { metadata: parsed.data };
	} catch {
		warnings.push({ code: CredentialParsingError.FailFetchIssuerMetadata });
		return { metadata: null };
	}
}
