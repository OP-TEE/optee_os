// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2022, Linaro Limited
 */

#include <types_ext.h>
#include <util.h>
#include "pauth.h"

void pauth_strip_pac(uint64_t *lr)
{
	const uint64_t va_mask = GENMASK_64(CFG_LPAE_ADDR_SPACE_BITS - 1, 0);

	*lr = *lr & va_mask;
}
