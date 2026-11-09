// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <drivers/qcom/tme/tme_intf.h>
#include <drivers/qcom/tme/tme_intf_defs.h>
#include <string_ext.h>
#include <trace.h>

#include "provision_backend.h"

/*
 * Fuses are accessed through the security processor. It owns the supplies,
 * the clocks and the programming sequence, so there is nothing to set up
 * here, and it only exposes the corrected view of a row. The status of the
 * fuse driver behind it is reported separately from the transport result and
 * must be checked as well.
 */

static TEE_Result tme_backend_nop(void)
{
	return TEE_SUCCESS;
}

static TEE_Result tme_backend_read_row(uint32_t addr, uint32_t *data)
{
	uint32_t status = TME_QFPROM_STATUS_UNSET;
	TEE_Result res = TEE_ERROR_GENERIC;

	res = tme_fuse_read(TME_QFPROM_ADDR_SPACE_CORR, addr, data, &status);
	if (res != TEE_SUCCESS) {
		EMSG("Fuse read of row 0x%"PRIx32" failed: %#"PRIx32,
		     addr, res);
		return res;
	}
	if (status != TME_QFPROM_NO_ERR) {
		EMSG("Fuse read of row 0x%"PRIx32" rejected: %#"PRIx32,
		     addr, status);
		return TEE_ERROR_GENERIC;
	}

	return TEE_SUCCESS;
}

/* One row per request, so that the first failure stops the programming */
static TEE_Result tme_backend_write_row(uint32_t addr, uint32_t *data)
{
	uint32_t status = TME_QFPROM_STATUS_UNSET;
	TEE_Result res = TEE_ERROR_GENERIC;
	TMEFuse_t row = { .addr = addr };

	row.data[0] = data[0];
	row.data[1] = data[1];

	res = tme_fuse_write_multiple(&row, 1, &status);
	memzero_explicit(&row, sizeof(row));
	if (res != TEE_SUCCESS) {
		EMSG("Fuse write of row 0x%"PRIx32" failed: %#"PRIx32,
		     addr, res);
		return res;
	}
	if (status != TME_QFPROM_NO_ERR) {
		EMSG("Fuse write of row 0x%"PRIx32" rejected: %#"PRIx32,
		     addr, status);
		return TEE_ERROR_GENERIC;
	}

	return TEE_SUCCESS;
}

#ifdef PROVISION_WRITE_PERM_ADDR
static TEE_Result tme_backend_is_write_locked(bool *locked)
{
	uint32_t data[TME_QFPROM_FUSE_DATA_WORDS] = { 0 };
	TEE_Result res = TEE_ERROR_GENERIC;

	*locked = false;
	res = tme_backend_read_row(PROVISION_WRITE_PERM_ADDR, data);
	if (res == TEE_SUCCESS)
		*locked = data[0] & PROVISION_WRITE_PERM_MASK;
	memzero_explicit(data, sizeof(data));

	return res;
}
#endif

/*
 * The write-lock check is only available when the platform describes the
 * write permission row. Without it the engine skips the check.
 */
const struct provision_backend provision_backend_tme = {
	.begin = tme_backend_nop,
	.end = tme_backend_nop,
	.read_row = tme_backend_read_row,
	.write_row = tme_backend_write_row,
#ifdef PROVISION_WRITE_PERM_ADDR
	.is_write_locked = tme_backend_is_write_locked,
#endif
};
