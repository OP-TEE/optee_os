// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <drivers/qcom/qfprom/qfprom.h>

#include "provision_backend.h"

static TEE_Result qfprom_backend_read_row(uint32_t addr, uint32_t *data)
{
	return qfprom_read_row(addr, QFPROM_ADDR_SPACE_CORR, data);
}

static TEE_Result qfprom_backend_row_has_fec(uint32_t addr, bool *has_fec)
{
	uint8_t fec = 0;
	TEE_Result res = TEE_ERROR_GENERIC;

	res = qfprom_row_has_fec_bits(addr, QFPROM_ADDR_SPACE_RAW, &fec);
	if (res == TEE_SUCCESS)
		*has_fec = fec;

	return res;
}

const struct provision_backend provision_backend_qfprom = {
	.begin = qfprom_hw_init,
	.end = qfprom_hw_deinit,
	.read_row = qfprom_backend_read_row,
	.write_row = qfprom_write_row,
	.row_has_fec = qfprom_backend_row_has_fec,
	.is_write_locked = qfprom_is_secboot_write_disabled,
};
