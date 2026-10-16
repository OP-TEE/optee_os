/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef PAS_ELF_H
#define PAS_ELF_H

#include <elf_common.h>
#include <stdbool.h>
#include <stdint.h>

#define MI_PBT_PAGE_MODE_MASK		0x00100000
#define MI_PBT_PAGE_MODE_SHIFT		20
#define MI_PBT_ACCESS_TYPE_MASK		0x00E00000
#define MI_PBT_ACCESS_TYPE_SHIFT	21
#define MI_PBT_SEGMENT_TYPE_MASK	0x07000000
#define MI_PBT_SEGMENT_TYPE_SHIFT	24

#define MI_PBT_NON_PAGED_SEGMENT	0x0
#define MI_PBT_HASH_SEGMENT		0x2
#define MI_PBT_NOTUSED_SEGMENT		0x3
#define MI_PBT_SHARED_SEGMENT		0x4

#define MI_PBT_PAGE_MODE(x) \
	(((x) & MI_PBT_PAGE_MODE_MASK) >> MI_PBT_PAGE_MODE_SHIFT)
#define MI_PBT_ACCESS_TYPE(x) \
	(((x) & MI_PBT_ACCESS_TYPE_MASK) >> MI_PBT_ACCESS_TYPE_SHIFT)
#define MI_PBT_SEGMENT_TYPE(x) \
	(((x) & MI_PBT_SEGMENT_TYPE_MASK) >> MI_PBT_SEGMENT_TYPE_SHIFT)

/*
 * pas_elf_is_image_seg() : select the program headers that describe segments
 * of the image proper: non-paged PT_LOAD segments other than the hash segment
 * and unused or shared ones. Only the type and flags are looked at; offsets,
 * addresses and sizes are not checked.
 *
 * @p_type:  program header type
 * @p_flags: program header flags
 */
static inline bool pas_elf_is_image_seg(uint32_t p_type, uint32_t p_flags)
{
	if (p_type != PT_LOAD)
		return false;

	return MI_PBT_PAGE_MODE(p_flags) == MI_PBT_NON_PAGED_SEGMENT &&
	       MI_PBT_SEGMENT_TYPE(p_flags) != MI_PBT_HASH_SEGMENT &&
	       MI_PBT_ACCESS_TYPE(p_flags) != MI_PBT_NOTUSED_SEGMENT &&
	       MI_PBT_ACCESS_TYPE(p_flags) != MI_PBT_SHARED_SEGMENT;
}

#endif /* PAS_ELF_H */
