/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * Copyright (c) 2026, Arm Limited
 */

#include <generated/arm32_sysreg.S>
#ifdef _CFG_ARM_V3_OR_V4
#include <generated/arm32_gicv3_sysreg.S>
#endif

	.macro mov_imm reg, val
		.if ((\val) & 0xffff0000) == 0
			movw	\reg, #(\val)
		.else
			movw	\reg, #((\val) & 0xffff)
			movt	\reg, #((\val) >> 16)
		.endif
	.endm

	.macro panic_at_smc_return
#if defined(CFG_TEE_CORE_DEBUG)
		bl	__panic_at_smc_return
#else
		b	.
#endif
	.endm
