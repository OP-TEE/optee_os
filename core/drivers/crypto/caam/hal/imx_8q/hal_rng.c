// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2020-2021, 2024 NXP
 */
#include <caam_hal_rng.h>
#include <caam_status.h>
#include <drivers/imx_sc_api.h>
#include <tee_api_types.h>
#include <trace.h>

enum caam_status caam_hal_rng_instantiated(vaddr_t baseaddr __unused)
{
	TEE_Result ret = TEE_ERROR_GENERIC;

	ret = imx_sc_seco_start_rng();
	if (ret != TEE_SUCCESS)
		return CAAM_FAILURE;
	else
		return CAAM_NO_ERROR;
}

bool caam_hal_rng_pr_enabled(vaddr_t baseaddr __unused)
{
	/*
	 * On platforms i.MX8Q and i.MX8DXL CAAM RNG Prediction
	 * resistance is enabled by default. So returning true.
	 */
	return true;
}
