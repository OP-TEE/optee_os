// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

/*
 * PIL anti-rollback fuse counter access for Lemans.
 *
 * The ARB counter is split into an LSB and MSB word. On this target both
 * words live in the same row (ANTI_ROLLBACK_9): LSB is word 0, MSB is
 * word 1.
 */

#include <qfprom_target.h>

#include "qfprom_priv.h"

#define PIL_VERSION_LSB_MSK	GENMASK_32(31, 0)
#define PIL_VERSION_MSB_MSK	GENMASK_32(27, 0)

TEE_Result qfprom_target_read_pil_arb(uint32_t *lsb, uint32_t *msb)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t row[2] = { };

	res = qfprom_read_row_locked(ANTI_ROLLBACK_9_ADDR,
				     QFPROM_ADDR_SPACE_CORR, row);
	if (res)
		return res;

	*lsb = row[0] & PIL_VERSION_LSB_MSK;
	*msb = row[1] & PIL_VERSION_MSB_MSK;

	return TEE_SUCCESS;
}

TEE_Result qfprom_target_write_pil_arb_lsb(uint32_t version)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t row[2] = { };

	res = qfprom_read_row(ANTI_ROLLBACK_9_ADDR, QFPROM_ADDR_SPACE_CORR,
			      row);
	if (res)
		return res;

	/* Preserve the MSB word and all bits outside the counter field. */
	row[0] |= unary_mask(version);
	return qfprom_write_row(ANTI_ROLLBACK_9_ADDR, row);
}

TEE_Result qfprom_target_write_pil_arb_msb(uint32_t version)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t row[2] = { };

	res = qfprom_read_row(ANTI_ROLLBACK_9_ADDR, QFPROM_ADDR_SPACE_CORR,
			      row);
	if (res)
		return res;

	/* Preserve the LSB word and all bits outside the counter field. */
	row[1] |= unary_mask(version);
	return qfprom_write_row(ANTI_ROLLBACK_9_ADDR, row);
}
