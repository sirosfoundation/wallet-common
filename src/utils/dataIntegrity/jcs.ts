/**
 * JSON Canonicalization Scheme (RFC 8785).
 *
 * Used by the `*-jcs-*` Data Integrity cryptosuites, which canonicalize the
 * plain JSON rather than the RDF dataset — so unlike the `*-rdfc-*` suites
 * this needs no JSON-LD processing or context resolution at all.
 */

/**
 * Serialize a number per RFC 8785 §3.2.2.3, which defers to ECMAScript's
 * Number::toString. `JSON.stringify` already implements exactly that for
 * finite numbers, so the only work here is rejecting the values JSON cannot
 * represent.
 */
function canonicalizeNumber(value: number): string {
	if (!Number.isFinite(value)) {
		throw new Error("JCS: NaN and Infinity are not serializable");
	}
	// -0 serializes as "0" per the spec's reference to Number::toString.
	if (Object.is(value, -0)) return "0";
	return JSON.stringify(value) as string;
}

/**
 * Serialize a string per RFC 8785 §3.2.2.2. `JSON.stringify` produces the
 * required escaping (shortest form, lowercase hex \u escapes for control
 * characters) and leaves lone surrogates intact, which is what the spec asks
 * for.
 */
function canonicalizeString(value: string): string {
	return JSON.stringify(value);
}

/**
 * Sort object keys by their UTF-16 code units, as RFC 8785 §3.2.3 requires.
 * JavaScript's default string comparison is already code-unit ordered, so a
 * plain `<` comparison is correct here.
 */
function sortKeys(keys: string[]): string[] {
	// Object.keys never repeats a key, so the two are never equal here.
	return [...keys].sort((a, b) => (a < b ? -1 : 1));
}

export function canonicalizeJcs(value: unknown): string {
	if (value === null) return "null";

	switch (typeof value) {
		case "boolean":
			return value ? "true" : "false";
		case "number":
			return canonicalizeNumber(value);
		case "string":
			return canonicalizeString(value);
		case "object":
			break;
		default:
			// undefined, function, symbol, bigint have no JSON representation.
			throw new Error(`JCS: value of type ${typeof value} is not serializable`);
	}

	if (Array.isArray(value)) {
		return `[${value.map((item) => canonicalizeJcs(item)).join(",")}]`;
	}

	const record = value as Record<string, unknown>;
	const entries = sortKeys(Object.keys(record))
		// Members whose value is undefined are omitted, matching JSON.stringify.
		.filter((key) => record[key] !== undefined)
		.map((key) => `${canonicalizeString(key)}:${canonicalizeJcs(record[key])}`);

	return `{${entries.join(",")}}`;
}
