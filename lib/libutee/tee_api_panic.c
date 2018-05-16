// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */
#include <tee_api.h>
#include <utee_syscalls.h>

/* System API - Misc */

void TEE_Panic(TEE_Result panicCode)
{
	utee_panic(panicCode);
}
