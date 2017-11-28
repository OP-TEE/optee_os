/*
 * Copyright (c) 2016-2017, Linaro Limited
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
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

static inline unsigned int atomic_load_uint(unsigned int *p)
{
	return __compiler_atomic_load(p);
}

static inline unsigned int atomic_load_u32(unsigned int *p)
{
	return __compiler_atomic_load(p);
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
