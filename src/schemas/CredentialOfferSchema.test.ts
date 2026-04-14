import { describe, it, expect } from 'vitest';
import { CredentialOfferSchema } from './CredentialOfferSchema';

describe("CredentialOfferSchema", () => {
	it("should parse authorization_code grant", () => {
		const offer = {
			credential_issuer: "https://issuer.example.com",
			credential_configuration_ids: ["pid-sd-jwt"],
			grants: {
				authorization_code: {
					issuer_state: "abc123"
				}
			}
		};
		const result = CredentialOfferSchema.safeParse(offer);
		expect(result.success).toBe(true);
		if (result.success) {
			expect(result.data.grants.authorization_code?.issuer_state).toBe("abc123");
		}
	});

	it("should parse pre-authorized_code grant with tx_code", () => {
		const offer = {
			credential_issuer: "https://issuer.example.com",
			credential_configuration_ids: ["pid-sd-jwt"],
			grants: {
				"urn:ietf:params:oauth:grant-type:pre-authorized_code": {
					"pre-authorized_code": "SplxlOBeZQQYbYS6WxSbIA",
					"tx_code": {
						"input_mode": "numeric",
						"length": 6,
						"description": "Enter the PIN sent via SMS"
					}
				}
			}
		};
		const result = CredentialOfferSchema.safeParse(offer);
		expect(result.success).toBe(true);
		if (result.success) {
			const preAuth = result.data.grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"];
			expect(preAuth?.["pre-authorized_code"]).toBe("SplxlOBeZQQYbYS6WxSbIA");
			expect(preAuth?.tx_code?.input_mode).toBe("numeric");
			expect(preAuth?.tx_code?.length).toBe(6);
			expect(preAuth?.tx_code?.description).toBe("Enter the PIN sent via SMS");
		}
	});

	it("should parse pre-authorized_code grant without tx_code", () => {
		const offer = {
			credential_issuer: "https://issuer.example.com",
			credential_configuration_ids: ["pid-sd-jwt"],
			grants: {
				"urn:ietf:params:oauth:grant-type:pre-authorized_code": {
					"pre-authorized_code": "SplxlOBeZQQYbYS6WxSbIA"
				}
			}
		};
		const result = CredentialOfferSchema.safeParse(offer);
		expect(result.success).toBe(true);
		if (result.success) {
			const preAuth = result.data.grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"];
			expect(preAuth?.["pre-authorized_code"]).toBe("SplxlOBeZQQYbYS6WxSbIA");
			expect(preAuth?.tx_code).toBeUndefined();
		}
	});

	it("should reject non-integer tx_code length", () => {
		const offer = {
			credential_issuer: "https://issuer.example.com",
			credential_configuration_ids: ["pid-sd-jwt"],
			grants: {
				"urn:ietf:params:oauth:grant-type:pre-authorized_code": {
					"pre-authorized_code": "abc",
					"tx_code": {
						"length": 5.5
					}
				}
			}
		};
		const result = CredentialOfferSchema.safeParse(offer);
		expect(result.success).toBe(false);
	});

	it("should preserve unknown future grant types via catchall", () => {
		const offer = {
			credential_issuer: "https://issuer.example.com",
			credential_configuration_ids: ["pid-sd-jwt"],
			grants: {
				"authorization_code": {
					"issuer_state": "state1"
				},
				"urn:example:future-grant-type": {
					"custom_field": "value"
				}
			}
		};
		const result = CredentialOfferSchema.safeParse(offer);
		expect(result.success).toBe(true);
		if (result.success) {
			expect(result.data.grants["urn:example:future-grant-type"]).toEqual({
				"custom_field": "value"
			});
		}
	});

	it("should parse offer with both grant types", () => {
		const offer = {
			credential_issuer: "https://issuer.example.com",
			credential_configuration_ids: ["pid-sd-jwt"],
			grants: {
				"authorization_code": {
					"issuer_state": "state1"
				},
				"urn:ietf:params:oauth:grant-type:pre-authorized_code": {
					"pre-authorized_code": "code123",
					"tx_code": {
						"length": 4,
						"input_mode": "numeric"
					}
				}
			}
		};
		const result = CredentialOfferSchema.safeParse(offer);
		expect(result.success).toBe(true);
		if (result.success) {
			expect(result.data.grants.authorization_code?.issuer_state).toBe("state1");
			expect(result.data.grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"]?.["pre-authorized_code"]).toBe("code123");
		}
	});

	it("should reject missing pre-authorized_code field", () => {
		const offer = {
			credential_issuer: "https://issuer.example.com",
			credential_configuration_ids: ["pid-sd-jwt"],
			grants: {
				"urn:ietf:params:oauth:grant-type:pre-authorized_code": {
					"tx_code": { "length": 6 }
				}
			}
		};
		const result = CredentialOfferSchema.safeParse(offer);
		expect(result.success).toBe(false);
	});
});
