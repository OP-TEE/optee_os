/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2018, Linaro Limited
 */
#include <malloc.h>
#include <stddef.h>
#include <util.h>

static inline void *unw_grow(void *p, size_t *cur_size, size_t new_size)
{
	if (*cur_size >= new_size)
		return p;

	size_t rounded_size = ROUNDUP(new_size, 16 * sizeof(vaddr_t));
	void *tmp = realloc(p, rounded_size);

	if (tmp)
		*cur_size = rounded_size;
	return tmp;
}
