import { CredentialParsingError } from "./error";
import { CredentialParser, ParsingEngineI } from "./interfaces";

export function ParsingEngine(): ParsingEngineI {
	const parsers: CredentialParser[] = [];

	return {
		register(parser: CredentialParser) {
			parsers.push(parser);
		},

		async parse({ rawCredential, credentialIssuer }) {
			// A parser that throws has told us nothing about whether a *later*
			// parser could handle the credential, so remember the failure and
			// keep going rather than failing the whole chain on it.
			let thrown = false;

			for (const parser of parsers) {
				try {
					const result = await parser.parse({ rawCredential, credentialIssuer });

					// Parser not supported this format, try next parser
					if (!result.success && result.error === CredentialParsingError.UnsupportedFormat) {
						continue;
					}

					// Otherwise return immediately
					return result;

				} catch {
					thrown = true;
					continue;
				}
			}

			// No parser handled it
			return {
				success: false,
				error: thrown ? CredentialParsingError.UnknownError : CredentialParsingError.UnsupportedFormat,
			};
		}
	};
}
