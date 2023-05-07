// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2022 NXP
 */

#include <riscv.h>
#include <kernel/panic.h>

void cpu_idle(void)
{
	/* ensure memory operations were complete */
	mb();
	/* stall the hart */
	wfi();
}
