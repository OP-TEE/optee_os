// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2022-2023, ARM Limited and Contributors. All rights reserved.
 *
 * Copyright (C) 2022-2023 Nuvoton Ltd.
 */

#include <kernel/linker.h>
#include <trace.h>
#include <npcm845x_utils.h>

void print_version(void)
{
	MSG_COLOR(COLOR_MAGENTA);
	MSG_COLOR(">================================================");
	MSG_COLOR("OP-TEE OS Version %s", core_v_str);
	MSG_COLOR(">================================================");
	MSG_COLOR(COLOR_NORMAL);
}
