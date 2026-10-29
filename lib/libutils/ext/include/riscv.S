/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2023 Andes Technology Corporation
 * Copyright (c) 2026, RISCStar Solutions Limited
 * Copyright 2026 NXP
 */

#if __riscv_xlen == 32
#define STR       sw
#define LDR       lw
#define REGOFF(x) ((x) * 4)
#elif __riscv_xlen == 64
#define STR       sd
#define LDR       ld
#define REGOFF(x) ((x) * 8)
#endif

#if __riscv_flen == 32
#define FSTR      fsw
#define FLDR      flw
#elif __riscv_flen == 64
#define FSTR      fsd
#define FLDR      fld
#endif

/*
 * User mode CFI (Zicfilp landing pads, Zicfiss shadow stacks): the
 * GNU_PROPERTY_RISCV_FEATURE_1_AND note the compiler emits for C is
 * ANDed by the linker over every input object, so assembly objects of
 * the libraries linked with TAs and of ldelf must carry it too or the
 * final ELF loses the property. The value is the set of features the
 * build enables.
 */
#include <elf_common.h>

#if !defined(__KERNEL__) && defined(CFG_TA_ZICFILP)
#define RISCV_TA_FEATURE_1_LP	GNU_PROPERTY_RISCV_FEATURE_1_CFI_LP_UNLABELED
#else
#define RISCV_TA_FEATURE_1_LP	0
#endif
#if !defined(__KERNEL__) && defined(CFG_TA_ZICFISS)
#define RISCV_TA_FEATURE_1_SS	GNU_PROPERTY_RISCV_FEATURE_1_CFI_SS
#else
#define RISCV_TA_FEATURE_1_SS	0
#endif
#define RISCV_TA_FEATURE_1_AND	(RISCV_TA_FEATURE_1_LP | RISCV_TA_FEATURE_1_SS)

#if __riscv_xlen == 32
#define RISCV_NOTE_P2ALIGN 2
#else
#define RISCV_NOTE_P2ALIGN 3
#endif

.macro emit_riscv_feature_1_and, feat
	.pushsection .note.gnu.property, "a"
	.p2align RISCV_NOTE_P2ALIGN
	.long	2f - 1f				/* n_namesz */
	.long	6f - 3f				/* n_descsz */
	.long	NT_GNU_PROPERTY_TYPE_0		/* n_type */
1:	.string "GNU"				/* name */
2:
	.p2align RISCV_NOTE_P2ALIGN
3:	.long	GNU_PROPERTY_RISCV_FEATURE_1_AND /* pr_type */
	.long	5f - 4f				/* pr_datasz */
4:	.long	\feat				/* property */
5:
	.p2align RISCV_NOTE_P2ALIGN
6:
	.popsection
.endm
