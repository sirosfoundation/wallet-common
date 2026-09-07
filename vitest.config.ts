import { defineConfig } from 'vitest/config';

/**
 * Files added or changed for W3C VCDM 2.0 support.
 *
 * These are held to full coverage via the per-file thresholds below, so a
 * regression in this area fails the run rather than quietly lowering an
 * overall average. The rest of the package has no coverage gate yet.
 */
export const VCDM2_FILES = [
	'src/credential-parsers/VCDM2JoseParser.ts',
	'src/credential-parsers/VCDM2LdpParser.ts',
	'src/credential-verifiers/VCDM2JoseVerifier.ts',
	'src/credential-verifiers/VCDM2LdpVerifier.ts',
	'src/schemas/Vcdm2CredentialSchema.ts',
	'src/utils/vcdm2.ts',
	'src/utils/vcdm2Presentation.ts',
	'src/utils/dataIntegrity/jcs.ts',
	'src/utils/dataIntegrity/multibase.ts',
	'src/utils/dataIntegrity/documentLoader.ts',
	'src/utils/dataIntegrity/verifyDataIntegrityProof.ts',
	'src/utils/detectCredentialFormat.ts',
	'src/ParsingEngine.ts',
];

export default defineConfig({
	test: {
		environment: 'node',
		include: ['**/*.test.ts'],
		exclude: ['node_modules/**'],
		silent: 'passed-only',
		coverage: {
			provider: 'v8',
			reporter: ['text', 'lcov'],
			reportsDirectory: 'coverage',
			include: VCDM2_FILES,
			thresholds: {
				100: true,
			},
		},
	},
});
