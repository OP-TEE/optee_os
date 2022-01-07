// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2022, Linaro Limited
 *
 */

#include <tee_api_types.h>
#include <tpm2_platform.h>
#include <trace.h>

TEE_Result test_tpm2(struct tpm2_mmio_data *md)
{
	(void)md;
	DMSG("Call tpm2_startup() and other cmds here");
	return TEE_SUCCESS;
}

