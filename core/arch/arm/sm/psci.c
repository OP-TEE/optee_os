// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2016 Freescale Semiconductor, Inc.
 * All rights reserved.
 *
 * Peng Fan <peng.fan@nxp.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <console.h>
#include <kernel/boot.h>
#include <kernel/thread.h>
#include <stdint.h>
#include <sm/optee_smc.h>
#include <sm/psci.h>
#include <sm/sm.h>
#include <trace.h>

__weak uint32_t psci_version(void)
{
	return PSCI_VERSION_1_1;
}

__weak int psci_cpu_suspend(uint32_t power_state __unused,
			    uintptr_t entry __unused,
			    uint32_t context_id __unused,
			    struct sm_nsec_ctx *nsec __unused)
{
	return PSCI_RET_NOT_SUPPORTED;
}

__weak int psci_cpu_off(void)
{
	return PSCI_RET_NOT_SUPPORTED;
}

__weak int psci_cpu_on(uint32_t cpu_id __unused, uint32_t entry __unused,
		       uint32_t context_id __unused)
{
	return PSCI_RET_NOT_SUPPORTED;
}

__weak int psci_affinity_info(uint32_t affinity __unused,
			      uint32_t lowest_affnity_level __unused)
{
	return PSCI_RET_NOT_SUPPORTED;
}

__weak int psci_migrate(uint32_t cpu_id __unused)
{
	return PSCI_RET_NOT_SUPPORTED;
}

__weak int psci_migrate_info_type(void)
{
	return PSCI_RET_NOT_SUPPORTED;
}

__weak int psci_migrate_info_up_cpu(void)
{
	return PSCI_RET_NOT_SUPPORTED;
}

__weak void psci_system_off(void)
{
}

__weak void psci_system_reset(void)
{
}

__weak int psci_features(uint32_t psci_fid __unused)
{
	return PSCI_RET_NOT_SUPPORTED;
}

__weak int psci_mem_protect(uint32_t enable __unused)
{
	return PSCI_RET_NOT_SUPPORTED;
}

__weak int psci_mem_chk_range(paddr_t base __unused,
			      size_t length __unused)
{
	return PSCI_RET_NOT_SUPPORTED;
}

__weak int psci_system_reset2(uint32_t reset_type __unused,
			      uint32_t cookie __unused)
{
	return PSCI_RET_NOT_SUPPORTED;
}

__weak int psci_node_hw_state(uint32_t cpu_id __unused,
			      uint32_t power_level __unused)
{
	return PSCI_RET_NOT_SUPPORTED;
}

__weak int psci_system_suspend(uintptr_t entry __unused,
			       uint32_t context_id __unused,
			       struct sm_nsec_ctx *nsec __unused)
{
	return PSCI_RET_NOT_SUPPORTED;
}

__weak int psci_stat_residency(uint32_t cpu_id __unused,
			       uint32_t power_state __unused)
{
	return PSCI_RET_NOT_SUPPORTED;
}

__weak int psci_stat_count(uint32_t cpu_id __unused,
			   uint32_t power_state __unused)
{
	return PSCI_RET_NOT_SUPPORTED;
}

void tee_psci_handler(struct thread_smc_args *args, struct sm_nsec_ctx *nsec)
{
	uint32_t smc_fid = args->a0;
	uint32_t a1 = args->a1;
	uint32_t a2 = args->a2;
	uint32_t a3 = args->a3;

	switch (smc_fid) {
	case PSCI_VERSION:
		args->a0 = psci_version();
		break;
	case PSCI_CPU_SUSPEND:
		args->a0 = psci_cpu_suspend(a1, a2, a3, nsec);
		break;
	case PSCI_CPU_OFF:
		args->a0 = psci_cpu_off();
		break;
	case PSCI_CPU_ON:
		args->a0 = psci_cpu_on(a1, a2, a3);
		break;
	case PSCI_AFFINITY_INFO:
		args->a0 = psci_affinity_info(a1, a2);
		break;
	case PSCI_MIGRATE:
		args->a0 = psci_migrate(a1);
		break;
	case PSCI_MIGRATE_INFO_TYPE:
		args->a0 = psci_migrate_info_type();
		break;
	case PSCI_MIGRATE_INFO_UP_CPU:
		args->a0 = psci_migrate_info_up_cpu();
		break;
	case PSCI_SYSTEM_OFF:
		psci_system_off();
		while (1)
			;
		break;
	case PSCI_SYSTEM_RESET:
		psci_system_reset();
		while (1)
			;
		break;
	case PSCI_PSCI_FEATURES:
		args->a0 = psci_features(a1);
		break;
	case PSCI_SYSTEM_RESET2:
		args->a0 = psci_system_reset2(a1, a2);
		break;
	case PSCI_MEM_PROTECT:
		args->a0 = psci_mem_protect(a1);
		break;
	case PSCI_MEM_PROTECT_CHECK_RANGE:
		args->a0 = psci_mem_chk_range(a1, a2);
		break;
	case PSCI_NODE_HW_STATE:
		args->a0 = psci_node_hw_state(a1, a2);
		break;
	case PSCI_SYSTEM_SUSPEND:
		args->a0 = psci_system_suspend(a1, a2, nsec);
		break;
	default:
		args->a0 = OPTEE_SMC_RETURN_UNKNOWN_FUNCTION;
		break;
	}
}
