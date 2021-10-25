// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2020-2021 NXP
 */
#include <caam_common.h>
#include <caam_hal_jr.h>
#include <drivers/imx_sc_api.h>
#include <tee_api_types.h>
#include <trace.h>

enum caam_status caam_hal_jr_setowner(vaddr_t ctrl_base __unused,
				      paddr_t jr_offset __unused,
				      enum caam_jr_owner owner __unused)
{
	TEE_Result ret = TEE_ERROR_GENERIC;

	ret = imx_sc_driver_init();
	if (ret != TEE_SUCCESS)
		return CAAM_FAILURE;

	ret = imx_sc_rm_enable_jr(CFG_JR_INDEX);
	if (ret != TEE_SUCCESS)
		return CAAM_FAILURE;
	else
		return CAAM_NO_ERROR;
}

void caam_hal_jr_prepare_backup(vaddr_t ctrl_base __unused,
				paddr_t jr_offset __unused)
{
}
