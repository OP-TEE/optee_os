// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2020, Linaro Limited
 */

#include <console.h>
#include <io.h>
#include <kernel/tee_misc.h>
#include <mm/core_memprot.h>
#include <sm/optee_smc.h>
#include <sm/sm.h>

#include "rzn1_regauth.h"

#define RZN1_OEM_CONSOLE_PUTC		0x01
#define RZN1_OEM_SYSREG_AUTH		0x10

static const struct regauth_t regauth_pass = {.rmask = ~0U, .wmask = ~0U};

static const struct regauth_t *get_regauth(unsigned long paddr)
{
	unsigned int idx = 0;
	unsigned int len = ARRAY_SIZE(regauth);

	while (idx < len) {
		if (core_is_buffer_inside(paddr, sizeof(uint32_t),
					  regauth[idx].paddr,
					  regauth[idx].size))
			return &regauth[idx];
		idx++;
	}

	return NULL;
}

static uint32_t oem_sysreg(uint32_t addr, uint32_t mask, uint32_t *pvalue)
{
	vaddr_t reg = 0;
	const struct regauth_t *auth = get_regauth(addr);

	/* Allow operations on registers not in the list */
	if (!auth)
		auth = &regauth_pass;

	reg = core_mmu_get_va(addr, MEM_AREA_IO_SEC, sizeof(uint32_t));

	if (mask) {
		/* Write operation */
		mask &= auth->wmask;
		if (!reg || !mask)
			DMSG("Blocking write of 0x%"PRIx32" to register 0x%"
			     PRIx32" (0x%"PRIxVA")", *pvalue, addr, reg);
		else
			io_mask32(reg, *pvalue, mask);
	} else {
		/* Read operation */
		if (!reg || !auth->rmask)
			DMSG("Blocking read of register 0x%"PRIx32" (0x%"
			     PRIxVA")", addr, reg);
		else
			*pvalue = io_read32(reg) & auth->rmask;
	}

	return 0;
}

static enum sm_handler_ret oem_service(struct sm_ctx *ctx __unused,
				       struct thread_smc_args *args)
{
	switch (OPTEE_SMC_FUNC_NUM(args->a0)) {
	case RZN1_OEM_SYSREG_AUTH:
		args->a0 = oem_sysreg(args->a1, args->a2, &args->a3);
		args->a1 = args->a3;
		break;
	case RZN1_OEM_CONSOLE_PUTC:
		console_putc(args->a1);
		break;
	default:
		return SM_HANDLER_PENDING_SMC;
	}

	return SM_HANDLER_SMC_HANDLED;
}

enum sm_handler_ret sm_platform_handler(struct sm_ctx *ctx)
{
	struct thread_smc_args *args = (void *)&ctx->nsec.r0;

	if (!OPTEE_SMC_IS_FAST_CALL(args->a0))
		return SM_HANDLER_PENDING_SMC;

	switch (OPTEE_SMC_OWNER_NUM(args->a0)) {
	case OPTEE_SMC_OWNER_OEM:
		return oem_service(ctx, args);
	default:
		return SM_HANDLER_PENDING_SMC;
	}
}
