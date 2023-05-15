/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2016-2019, Linaro Limited
 */

#ifndef __ATOMIC_H
#define __ATOMIC_H

#include <compiler.h>
#include <types_ext.h>

uint32_t atomic_inc32(volatile uint32_t *v);
uint32_t atomic_dec32(volatile uint32_t *v);

static inline bool atomic_cas_uint(unsigned int *p, unsigned int *oval,
				   unsigned int nval)
{
	return __compiler_compare_and_swap(p, oval, nval);
}

static inline bool atomic_cas_u32(uint32_t *p, uint32_t *oval, uint32_t nval)
{
	return __compiler_compare_and_swap(p, oval, nval);
}

static inline int atomic_load_int(int *p)
{
	return __compiler_atomic_load(p);
}

static inline short int atomic_load_short(short int *p)
{
	return __compiler_atomic_load(p);
}

static inline unsigned int atomic_load_uint(unsigned int *p)
{
	return __compiler_atomic_load(p);
}

static inline uint32_t atomic_load_u32(const uint32_t *p)
{
	return __compiler_atomic_load(p);
}

static inline void atomic_store_int(int *p, int val)
{
	__compiler_atomic_store(p, val);
}

static inline void atomic_store_short(short int *p, short int val)
{
	__compiler_atomic_store(p, val);
}

static inline void atomic_store_uint(unsigned int *p, unsigned int val)
{
	__compiler_atomic_store(p, val);
}

static inline void atomic_store_u32(uint32_t *p, uint32_t val)
{
	__compiler_atomic_store(p, val);
}

#endif /*__ATOMIC_H*/
