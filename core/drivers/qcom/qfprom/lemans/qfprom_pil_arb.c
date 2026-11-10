// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

/*
 * The rollback version is a pair of saturating unary counters in the same
 * row (ANTI_ROLLBACK_9): the LSB counter is word 0 (32 bits) and the MSB
 * counter is word 1 (28 bits). The version is the number of bits set in
 * both.
 */

#include <qfprom_target.h>
#include <util.h>

#include "qfprom_priv.h"

#define PIL_VERSION_LSB_BITS	U(32)
#define PIL_VERSION_MSB_BITS	U(28)
#define PIL_VERSION_LSB_MSK	GENMASK_32(PIL_VERSION_LSB_BITS - 1, 0)
#define PIL_VERSION_MSB_MSK	GENMASK_32(PIL_VERSION_MSB_BITS - 1, 0)

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

	res = qfprom_read_row_locked(ANTI_ROLLBACK_9_ADDR,
				     QFPROM_ADDR_SPACE_CORR, row);
	if (res)
		return res;

	*version = popcount32(row[0] & PIL_VERSION_LSB_MSK) +
		   popcount32(row[1] & PIL_VERSION_MSB_MSK);

	return TEE_SUCCESS;
}

static TEE_Result blow_counter(unsigned int word, uint32_t nbits)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t row[2] = { };

	res = qfprom_read_row(ANTI_ROLLBACK_9_ADDR, QFPROM_ADDR_SPACE_CORR,
			      row);
	if (res)
		return res;

	row[word] |= unary_mask(nbits);
	return qfprom_write_row(ANTI_ROLLBACK_9_ADDR, row);
}

TEE_Result qfprom_target_blow_pil_arb(uint32_t version)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	/* Saturate each word at its capacity, programming the LSB first. */
	res = blow_counter(0, MIN(version, PIL_VERSION_LSB_BITS));
	if (res || version <= PIL_VERSION_LSB_BITS)
		return res;

	return blow_counter(1, MIN(version - PIL_VERSION_LSB_BITS,
				   PIL_VERSION_MSB_BITS));
}
