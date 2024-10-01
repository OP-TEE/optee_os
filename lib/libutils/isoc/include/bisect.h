/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2024, STMicroelectronics
 */
#ifndef __BISECT_H
#define __BISECT_H

#include <stddef.h>
#include <stdlib.h>

/*
 * Sort array in increasing order according to @cmp rule
 * @array: Array to sort for bisect support
 * @n: Number of cells in @array
 * @cell_size: Byte size of a single cell of @array
 * @cmp: Trilean comparision helper function applicable to @array
 */
static inline void bisect_sort(void *array, size_t n, size_t cell_size,
			       int (*cmp)(const void *, const void *))
{
	qsort(array, n, cell_size, cmp);
}

/*
 * Bisect into array to find the cell that matches an entry
 * @array: Sorted array (according the @cmp) to bisect in
 * @n: Number of cells in @array
 * @cell_size: Byte size of a single cell of @array
 * @target: Entry for which we find an equal entry (with @cmp) in sorted @array
 * @cmp: Trilean comparision helper function applicable to @array
 * @return: Pointer to the cell in @array matching @target, NULL if none found
 */
void *bisect_equal(const void *array, size_t n, size_t cell_size,
		   const void *target, int (*cmp)(const void *, const void *));

#endif /*__BISECT_H*/
