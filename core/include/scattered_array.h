/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2018, Linaro Limited
 */
#ifndef __SCATTERED_ARRAY_H
#define __SCATTERED_ARRAY_H

#include <compiler.h>
#include <keep.h>

/*
 * A scattered array is assembled from items declared in different source
 * files depending on something like "SORT(.scattered_array*)" in the link
 * script to get everything assembled in the right order.
 *
 * Whenever a new scattered array is created with the macros below there's
 * no need to update the link script.
 */

#define __SCT_ARRAY_DEF_ITEM3(element_type, element_name, section_name) \
	static const element_type element_name; \
	DECLARE_KEEP_INIT(element_name); \
	static const element_type element_name __used \
		__section(section_name)

#define __SCT_ARRAY_DEF_PG_ITEM3(element_type, element_name, section_name) \
	static const element_type element_name __used \
		__section(section_name)

#define __SCT_ARRAY_DEF_ITEM2(array_name, order, id, element_type) \
	__SCT_ARRAY_DEF_ITEM3(element_type, \
			      __scattered_array_ ## id ## array_name, \
			      ".scattered_array_" #array_name "_1_" #order)

#define __SCT_ARRAY_DEF_PG_ITEM2(array_name, order, id, element_type) \
	__SCT_ARRAY_DEF_PG_ITEM3(element_type, \
				 __scattered_array_ ## id ## array_name, \
				 ".scattered_array_" #array_name "_1_" #order)

#define __SCT_ARRAY_DEF_ITEM1(array_name, order, id, element_type) \
	__SCT_ARRAY_DEF_ITEM2(array_name, order, id, element_type)

#define __SCT_ARRAY_DEF_PG_ITEM1(array_name, order, id, element_type) \
	__SCT_ARRAY_DEF_PG_ITEM2(array_name, order, id, element_type)

/*
 * Defines an item in a scattered array, sorted based on @order.
 * @array_name:   Name of the scattered array
 * @order:        Tag on which this item is sorted in the array
 * @element_type: The type of the elemenet
 */
#define SCATTERED_ARRAY_DEFINE_ITEM_ORDERED(array_name, order, element_type) \
	__SCT_ARRAY_DEF_ITEM1(array_name, order, __COUNTER__, element_type)

/*
 * Same as SCATTERED_ARRAY_DEFINE_ITEM_ORDERED except that references
 * to other objects (for instance null terminated strings) are allowed
 * to reside in the paged area without residing in the init area
 */
#define SCATTERED_ARRAY_DEFINE_PG_ITEM_ORDERED(array_name, order, \
					       element_type) \
	__SCT_ARRAY_DEF_PG_ITEM1(array_name, order, __COUNTER__, element_type)

/*
 * Defines an item in a scattered array
 * @array_name:   Name of the scattered array
 * @element_type: The type of the elemenet
 */
#define SCATTERED_ARRAY_DEFINE_ITEM(array_name, element_type) \
	__SCT_ARRAY_DEF_ITEM1(array_name, 0, __COUNTER__, element_type)

/*
 * Same as SCATTERED_ARRAY_DEFINE_ITEM except that references to other
 * objects (for instance null terminated strings) are allowed to reside in
 * the paged area without residing in the init area
 */
#define SCATTERED_ARRAY_DEFINE_PG_ITEM(array_name, element_type) \
	__SCT_ARRAY_DEF_PG_ITEM1(array_name, 0, __COUNTER__, element_type)

/*
 * Returns the first element in a scattered array
 * @array_name:   Name of the scattered array
 * @element_type: The type of the elemenet
 */
#define SCATTERED_ARRAY_BEGIN(array_name, element_type) (__extension__({ \
		static const element_type __scattered_array_begin[0] __unused \
		__section(".scattered_array_" #array_name "_0"); \
		\
		(const element_type *)scattered_array_relax_ptr( \
			__scattered_array_begin); \
	}))

/*
 * Returns one entry past the last element in a scattered array
 * @array_name:   Name of the scattered array
 * @element_type: The type of the elemenet
 */
#define SCATTERED_ARRAY_END(array_name, element_type) (__extension__({ \
		static const element_type __scattered_array_end[0] __unused \
		__section(".scattered_array_" #array_name "_2"); \
		\
		__scattered_array_end; \
	}))

/*
 * Loop over all elements in the scattered array
 * @elem:	Iterator
 * @array_name:   Name of the scattered array
 * @element_type: The type of the elemenet
 */
#define SCATTERED_ARRAY_FOREACH(elem, array_name, element_type) \
	for ((elem) = SCATTERED_ARRAY_BEGIN(array_name, element_type); \
	     (elem) < SCATTERED_ARRAY_END(array_name, element_type); (elem)++)

/*
 * scattered_array_relax_ptr() - relax pointer attributes
 * @p	pointer to return
 *
 * If the pointer returned from the array __scattered_array_begin[] in
 * SCATTERED_ARRAY_BEGIN() is passed directly the compiler may notice that
 * it's an empty array and emit warnings. With the address passed via this
 * function the compiler will have no such knowledge about the pointer.
 *
 * Returns supplied pointer.
 */
const void *scattered_array_relax_ptr(const void *p) __attr_const;

#endif /*__SCATTERED_ARRAY_H*/

