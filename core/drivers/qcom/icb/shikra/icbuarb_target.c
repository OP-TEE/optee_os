// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *
 * Shikra ICB micro-arbiter target back-end.
 *
 * Provides icbuarb_target_get_info() and icbuarb_target_init() as required
 * by the common ICB micro-arbiter driver (icbuarb.c).
 */

#include "icbuarbi.h"

/* Shikra ICB configuration data (defined in u_data.c). */
extern struct icb_info info;

struct icb_info *icbuarb_target_get_info(void)
{
	return &info;
}

bool icbuarb_target_init(struct icb_info *icb_info_ptr)
{
	(void)icb_info_ptr;
	return true;
}
