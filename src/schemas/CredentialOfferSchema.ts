import { z } from 'zod'

export const CredentialOfferSchema = z.object({
	credential_issuer: z.string(),
	credential_configuration_ids: z.array(z.string()),
	grants: z.object({
		"authorization_code": z.object({
			"issuer_state": z.string().optional()
		}).optional(),
		"urn:ietf:params:oauth:grant-type:pre-authorized_code": z.object({
			"pre-authorized_code": z.string(),
			"tx_code": z.object({
				"input_mode": z.string().optional(),
				"length": z.number().int().positive().optional(),
				"description": z.string().optional(),
			}).optional(),
		}).optional(),
	}).catchall(z.record(z.unknown()))
})

export type CredentialOffer = z.infer<typeof CredentialOfferSchema>;
