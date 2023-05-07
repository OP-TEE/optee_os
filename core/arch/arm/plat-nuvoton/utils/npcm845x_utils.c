/*
 * Copyright (c) 2022-2023, ARM Limited and Contributors. All rights reserved.
 *
 * Copyright (C) 2022-2023 Nuvoton Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <kernel/linker.h>
#include <utils/npcm845x_trace.h>
#include <npcm845x_utils.h>

void print_version(void)
{
	TMSG(COLOR_MAGENTA);
	TMSG(">================================================");
	TMSG("OP-TEE OS Version %s", core_v_str);
	TMSG(">================================================");
	TMSG(COLOR_NORMAL);
}
