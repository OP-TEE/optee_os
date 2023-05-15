/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2021, Linaro Limited
 */

#include <elf_common.h>

/*
 * This macro emits a program property note section identifying
 * architecture features which require special handling, mainly for
 * use in assembly files in the libraries linked with TA's.
 */

.macro emit_aarch64_feature_1_and, feat
	.pushsection .note.gnu.property, "a"
	.align  3
	.long   2f - 1f				/* n_namesz */
	.long   6f - 3f				/* n_desc_sz */
	.long   NT_GNU_PROPERTY_TYPE_0		/* n_type */
1:      .string "GNU"				/* name */
2:
	.align  3
3:      .long   GNU_PROPERTY_AARCH64_FEATURE_1_AND 	/* pr_type */
	.long   5f - 4f					/* pr_datasz */
4:
	/*
	 * This is described with an array of char in the Linux API
	 * spec but the text and all other usage (including binutils,
	 * clang and GCC) treat this as a 32 bit value so no swizzling
	 * is required for big endian.
	 */
	.long   \feat					/* property */
5:
	.align  3
6:
	.popsection
.endm
