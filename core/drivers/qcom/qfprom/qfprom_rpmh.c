// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <drivers/qcom/cmd_db/cmd_db.h>
#include <drivers/qcom/rpmh/rpmh_client.h>
#include <inttypes.h>
#include <trace.h>

#include "qfprom_rpmh.h"

#define QFPROM_VREG_VOLTAGE_OFFSET	U(0)
#define QFPROM_VREG_ENABLE_OFFSET	U(4)
#define QFPROM_VREG_MODE_OFFSET		U(8)

static struct rpmh_client *qfprom_rpmh_handle;

static TEE_Result qfprom_rpmh_get_handle(void)
{
	if (!qfprom_rpmh_handle)
		qfprom_rpmh_handle = rpmh_create_handle(RSC_DRV_SECURE,
							"qfprom");

	return qfprom_rpmh_handle ? TEE_SUCCESS : TEE_ERROR_GENERIC;
}

TEE_Result qfprom_rpmh_vote_supply(const char *name, uint32_t voltage_mv,
				   uint32_t off_mode, bool enable)
{
	const uint32_t offsets[] = {
		QFPROM_VREG_MODE_OFFSET,
		QFPROM_VREG_VOLTAGE_OFFSET,
		QFPROM_VREG_ENABLE_OFFSET,
	};
	const uint32_t values[] = {
		enable ? QFPROM_VREG_MODE_NPM : off_mode,
		enable ? voltage_mv : 0,
		enable,
	};
	TEE_Result res = TEE_SUCCESS;
	TEE_Result ret = TEE_SUCCESS;
	uint32_t addr = 0;
	uint32_t req_id = 0;
	size_t i = 0;

	res = qfprom_rpmh_get_handle();
	if (res != TEE_SUCCESS)
		return res;

	res = cmd_db_get_addr(name, &addr);
	if (res != TEE_SUCCESS)
		return res;
	if (!addr)
		return TEE_ERROR_ITEM_NOT_FOUND;

	for (i = 0; i < ARRAY_SIZE(offsets); i++) {
		ret = rpmh_send_command(qfprom_rpmh_handle, RPMH_SET_ACTIVE,
					true, addr + offsets[i], values[i],
					&req_id);
		if (ret == TEE_SUCCESS)
			continue;

		EMSG("Supply %s key %"PRIu32" vote failed: %#"PRIx32,
		     name, offsets[i], ret);
		if (enable)
			return ret;
		if (res == TEE_SUCCESS)
			res = ret;
	}

	return res;
}

TEE_Result qfprom_rpmh_vote_mx(uint32_t level)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t vrm_addr = 0;
	uint32_t req_id = 0;

	res = qfprom_rpmh_get_handle();
	if (res != TEE_SUCCESS)
		return res;

	res = cmd_db_get_addr("mx.lvl", &vrm_addr);
	if (res == TEE_SUCCESS && !vrm_addr)
		res = TEE_ERROR_ITEM_NOT_FOUND;
	if (res == TEE_SUCCESS)
		res = rpmh_send_command(qfprom_rpmh_handle, RPMH_SET_ACTIVE,
					true, vrm_addr, level, &req_id);
	if (res != TEE_SUCCESS)
		EMSG("MX vote failed: %#"PRIx32, res);

	return res;
}
