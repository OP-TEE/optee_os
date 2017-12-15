/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, Linaro Limited
 */

#ifndef TEESMC_OPTEED_MACROS_H
#define TEESMC_OPTEED_MACROS_H

#define TEESMC_OPTEED_RV(func_num) \
	OPTEE_SMC_CALL_VAL(OPTEE_SMC_32, OPTEE_SMC_FAST_CALL, \
			   OPTEE_SMC_OWNER_TRUSTED_OS_OPTEED, (func_num))

#endif /*TEESMC_OPTEED_MACROS_H*/
