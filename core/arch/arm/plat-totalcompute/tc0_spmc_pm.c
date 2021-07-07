// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2021, Arm Limited
 */

#include <arm.h>
#include <kernel/boot.h>
#include <ffa.h>
#include <sm/psci.h>

void ffa_secondary_cpu_ep_register(vaddr_t secondary_ep)
{
	unsigned int ret = 0;

	/* Invoke FFA_SECONDARY_EP_REGISTER_64 to the SPMC */
	ret = thread_smc(FFA_SECONDARY_EP_REGISTER_64, secondary_ep, 0, 0);

	if (ret != FFA_SUCCESS_32 && ret != FFA_SUCCESS_64) {
		EMSG("FFA_SECONDARY_EP_REGISTER_64 ret %"PRId32, ret);
	}

	return;
}
