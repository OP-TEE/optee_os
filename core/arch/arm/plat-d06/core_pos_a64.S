/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015, Linaro Limited
 * Copyright (c) 2019, Arm Limited. All rights reserved.
 * Copyright (c) 2020, Marek Vasut
 * Copyright (c) 2022, Huawei Technologies Co., Ltd
 */

#include <asm.S>
#include <arm.h>
#include <arm64_macros.S>

/*
 *  bit8~bit10:  core index
 *  bit16~bit18: ccl index
 *  bit20~bit22: sccl index
 *  96 cores: index = sccl * 24 + ccl * 4 + core
 *  128 cores: index = sccl * 32 + ccl * 4 + core (now used)
 */

FUNC get_core_pos_mpidr , :
	lsr     x1, x0, 8
	and     x2, x1, 0x7

	lsr     x1, x0, 16
	and     x3, x1, 0x7

	lsr     x1, x0, 20
	and     x4, x1, 0x7

	mov     x5, x4
#if (CFG_TEE_CORE_NB_CORE == 96)
	lsl     x5, x5, 1
	add     x5, x5, x4
	lsl     x5, x5, 1
#elif (CFG_TEE_CORE_NB_CORE == 128)
	lsl     x5, x5, 3
#else
	static_assert(0);
#endif
	add     x5, x5, x3
	lsl     x5, x5, 2
	add     x5, x5, x2

	mov     x0, x5

	ret
END_FUNC get_core_pos_mpidr
