// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2024, Linaro Limited
 */

#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <string_ext.h>

void *ins_array_elem(void *base, size_t elem_count, size_t elem_size,
		     size_t pos, const void *elem)
{
	uint8_t *b = base;
	void *e = b + pos * elem_size;

	assert(pos < elem_count);

	memmove(b + (pos + 1) * elem_size, e,
		(elem_count - pos - 1) * elem_size);

	if (elem)
		memcpy(e, elem, elem_size);

	return e;
}

void *ins_array_elem_zero_init(void *base, size_t elem_count, size_t elem_size,
			       size_t pos)
{
	return memset(ins_array_elem(base, elem_count, elem_size, pos, NULL),
		      0, elem_size);
}

void rem_array_elem(void *base, size_t elem_count, size_t elem_size,
		    size_t pos)
{
	uint8_t *b = base;

	assert(pos < elem_count);

	memmove(b + pos * elem_size, b + (pos + 1) * elem_size,
		(elem_count - pos - 1) * elem_size);
}

void rem_array_elem_zero_pad(void *base, size_t elem_count, size_t elem_size,
			     size_t pos)
{
	rem_array_elem(base, elem_count, elem_size, pos);
	memset((uint8_t *)base + (elem_count - 1) * elem_size, 0, elem_size);
}
