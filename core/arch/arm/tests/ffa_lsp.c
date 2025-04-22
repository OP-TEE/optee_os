// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2025, Linaro Limited.
 */

#include <ffa.h>
#include <initcall.h>
#include <kernel/thread_spmc.h>
#include <sm/optee_smc.h>

static void test_direct_req(struct thread_smc_1_2_regs *args)
{
	uint16_t src = args->a1 >> 16;
	uint16_t dst = args->a1;

	if (OPTEE_SMC_IS_64(args->a0))
		args->a0 = FFA_MSG_SEND_DIRECT_RESP_64;
	else
		args->a0 = FFA_MSG_SEND_DIRECT_RESP_32;
	args->a1 = SHIFT_U32(dst, 16) | src;
	args->a2 = 0;
	args->a3 = args->a3 + args->a4 + args->a5 + args->a6 + args->a7;
}

static struct spmc_lsp_desc desc __nex_data = {
	.name = "Test LSP",
	.direct_req = test_direct_req,
	.properties = FFA_PART_PROP_DIRECT_REQ_RECV,
	/* UUID 54b5440e-a3d2-48d1-872a-7b6cbfc34855 */
	.uuid_words = { 0x0e44b554, 0xd148d2a3, 0x6c7b2a87, 0x5548c3bf, },
};

static TEE_Result lsp_init(void)
{
	return spmc_register_lsp(&desc);
}

nex_service_init_late(lsp_init);
