// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2017-2022, STMicroelectronics
 */

#include <drivers/stm32_shared_io.h>
#include <io.h>
#include <kernel/spinlock.h>
#include <stm32_util.h>

static unsigned int shregs_lock = SPINLOCK_UNLOCK;

static uint32_t lock_stm32shregs(void)
{
	return may_spin_lock(&shregs_lock);
}

static void unlock_stm32shregs(uint32_t exceptions)
{
	may_spin_unlock(&shregs_lock, exceptions);
}

void io_mask32_stm32shregs(vaddr_t va, uint32_t value, uint32_t mask)
{
	uint32_t exceptions = lock_stm32shregs();

	io_mask32(va, value, mask);

	unlock_stm32shregs(exceptions);
}

void io_clrsetbits32_stm32shregs(vaddr_t va, uint32_t clr, uint32_t set)
{
	uint32_t exceptions = lock_stm32shregs();

	io_clrsetbits32(va, clr, set);

	unlock_stm32shregs(exceptions);
}
