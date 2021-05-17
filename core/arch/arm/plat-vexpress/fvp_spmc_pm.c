// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2019-2021, Arm Limited
 */

#include <ffa.h>
#include <kernel/boot.h>
#include <kernel/panic.h>
#include <kernel/thread.h>

void ffa_secondary_cpu_ep_register(vaddr_t secondary_ep)
{
	unsigned long ret = 0;

	/*
	 * FFA_SECONDARY_EP_REGISTER_64 is handled by the SPMD if called by an
	 * S-EL1 SPMC at secure physical FF-A instance.
	 * It is handled by an S-EL2 SPMC if called by a SP at secure virtual
	 * FF-A instance.
	 */
	ret = thread_smc(FFA_SECONDARY_EP_REGISTER_64, secondary_ep, 0, 0);

	if (ret != FFA_SUCCESS_64) {
		EMSG("FFA_SECONDARY_EP_REGISTER_64 ret %ld", ret);
		panic();
	}
}
