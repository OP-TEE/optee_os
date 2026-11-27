// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

/*
 * PIL anti-rollback fuse access for Shikra.
 *
 * The counter is the LSB word of ANTI_ROLLBACK_2: one fuse bit per rollback
 * version, so its capacity is 32. The MSB word of the same row is not part
 * of the counter and is never modified here.
 */

#include <qfprom_target.h>

#include "qfprom_priv.h"

#define MAX_PIL_VERSION	U(32)

TEE_Result qfprom_target_pil_arb_enabled(bool *enabled)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t row[2] = { };

	res = qfprom_read_row_locked(PIL_ARB_EN_RAW_ADDR,
				     QFPROM_ADDR_SPACE_CORR, row);
	if (res)
		return res;

	*enabled = (row[1] & PIL_ARB_EN_BMSK) != 0;

	return TEE_SUCCESS;
}

TEE_Result qfprom_target_get_pil_arb(uint32_t *version)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t row[2] = { };

	res = qfprom_read_row_locked(ANTI_ROLLBACK_2_ADDR,
				     QFPROM_ADDR_SPACE_CORR, row);
	if (res)
		return res;

	*version = popcount32(row[0]);

	return TEE_SUCCESS;
}

TEE_Result qfprom_target_blow_pil_arb(uint32_t version)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t row[2] = { };

	res = qfprom_read_row(ANTI_ROLLBACK_2_ADDR, QFPROM_ADDR_SPACE_CORR,
			      row);
	if (res)
		return res;

	// Saturate the version before any checks/ fuse blow.
	version = MIN(version, MAX_PIL_VERSION);

	if (popcount32(row[0]) == version)
		return TEE_SUCCESS;

	/*
	 * Fuse bits can only be blown, never cleared. A partially failed
	 * blow can leave a gap such as 0b1001: refuse a version that ORing
	 * would overshoot.
	 */
	if (popcount32(row[0] | unary_mask(version)) != version)
		return TEE_ERROR_BAD_STATE;

	row[0] |= unary_mask(version);
	return qfprom_write_row(ANTI_ROLLBACK_2_ADDR, row);
}
