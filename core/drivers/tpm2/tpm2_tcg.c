// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2022, Linaro Limited
 */

#include <drivers/tpm2_chip.h>
#include <kernel/tcg.h>
#include <tpm2.h>

static TEE_Result tpm2_tcg_get_pcr_info(uint32_t *selection_mask,
					uint32_t *active_mask,
					uint32_t *num_pcr)
{
	struct tpm2_caps caps = { };
	enum tpm2_result rc = TPM2_OK;

	rc = tpm2_chip_get_caps(&caps);
	if (rc)
		return TEE_ERROR_COMMUNICATION;

	*num_pcr = caps.num_pcrs;
	*selection_mask = caps.selection_mask;
	*active_mask = caps.active_mask;

	return TEE_SUCCESS;
}

static TEE_Result tpm2_tcg_pcr_extend(uint8_t pcr_idx, uint16_t alg,
				      void *digest, uint32_t digest_len)
{
	if (tpm2_pcr_extend(pcr_idx, alg, digest, digest_len))
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}

static struct tcg_pcr_ops tpm2_tcg_ops = {
	.pcr_info = tpm2_tcg_get_pcr_info,
	.pcr_extend = tpm2_tcg_pcr_extend,
};

TEE_Result tpm2_tcg_register(void)
{
	return register_tcg_pcr_provider(&tpm2_tcg_ops);
}
