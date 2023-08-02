/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2023 Marvell.
 */

#include <asm.S>
#include <arm.h>
#include <arm64_macros.S>

FUNC get_core_pos_mpidr , :
/* No clusters, core position is affinity2 of MPIDR_EL1 */
	mov_imm x1, MPIDR_AFFLVL_MASK
	and     x0, x1, x0, LSR #MPIDR_AFF2_SHIFT
	ret
END_FUNC get_core_pos_mpidr
