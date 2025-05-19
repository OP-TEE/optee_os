/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2024, Linaro Limited
 */

#ifndef __MM_PAGE_ALLOC_H
#define __MM_PAGE_ALLOC_H

#include <malloc_flags.h>
#include <types_ext.h>
#include <util.h>

void nex_page_alloc_init(void);
void page_alloc_init(void);

vaddr_t virt_page_alloc(size_t count, uint32_t flags);
struct mobj *mobj_page_alloc(size_t count, uint32_t flags);

#endif /*__MM_PAGE_ALLOC_H*/
