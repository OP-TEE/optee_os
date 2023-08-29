/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2023 NXP
 * Copyright (c) 2014, Linaro Limited
 */

#ifndef TEEABI_OPTEED_MACROS_H
#define TEEABI_OPTEED_MACROS_H

#define TEEABI_OPTEED_RV(func_num) \
	OPTEE_ABI_CALL_VAL(OPTEE_ABI_32, OPTEE_ABI_FAST_CALL, \
			   OPTEE_ABI_OWNER_TRUSTED_OS_OPTEED, (func_num))

#endif /*TEEABI_OPTEED_MACROS_H*/
