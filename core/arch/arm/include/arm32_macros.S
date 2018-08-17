/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

#include <generated/arm32_sysreg.S>
#ifdef CFG_ARM_GICV3
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

