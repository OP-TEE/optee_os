// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2021, Linaro Limited
 */

#include <assert.h>
#include <drivers/rstctrl.h>
#include <io.h>
#include <kernel/dt.h>
#include <kernel/dt_driver.h>
#include <kernel/spinlock.h>
#include <libfdt.h>
#include <stdint.h>

/* Global reset controller access lock */

TEE_Result rstctrl_get_exclusive(struct rstctrl *rstctrl)
{
	uint32_t exceptions = 0;
	TEE_Result res = TEE_ERROR_ACCESS_CONFLICT;
	static unsigned int rstctrl_lock = SPINLOCK_UNLOCK;

	exceptions = cpu_spin_lock_xsave(&rstctrl_lock);

	if (!rstctrl->exclusive) {
		rstctrl->exclusive = true;
		res = TEE_SUCCESS;
	}

	cpu_spin_unlock_xrestore(&rstctrl_lock, exceptions);

	return res;
}

void rstctrl_put_exclusive(struct rstctrl *rstctrl)
{
	assert(rstctrl->exclusive);

	WRITE_ONCE(rstctrl->exclusive, false);
}

TEE_Result rstctrl_dt_get_by_name(const void *fdt, int nodeoffset,
				  const char *name, struct rstctrl **rstctrl)
{
	int index = 0;

	index = fdt_stringlist_search(fdt, nodeoffset, "reset-names", name);
	if (index < 0)
		return TEE_ERROR_GENERIC;

	return rstctrl_dt_get_by_index(fdt, nodeoffset, index, rstctrl);
}
