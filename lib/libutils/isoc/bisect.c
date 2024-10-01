// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2024, STMicroelectronics
 */

#include <bisect.h>

void *bisect_equal(const void *array, size_t n, size_t cell_size,
		   const void *target, int (*cmp)(const void *, const void *))
{
	const uint8_t *array_base = array;
	size_t high_index = 0;
	size_t low_index = 0;

	if (!array || !n)
		return NULL;

	high_index = n - 1;

	if (cmp(array_base + high_index * cell_size, target) < 0)
		return NULL;
	if (cmp(array_base + low_index * cell_size, target) > 0)
		return NULL;

	while (high_index > low_index) {
		size_t index = (high_index + low_index) / 2;
		int diff = cmp(array_base + index * cell_size, target);

		if (!diff)
			return (void *)(array_base + index * cell_size);

		if (diff > 0)
			high_index = index - 1;
		else
			low_index = index + 1;
	}

	if (cmp(array_base + low_index * cell_size, target) == 0)
		return (void *)(array_base + low_index * cell_size);

	return NULL;
}
