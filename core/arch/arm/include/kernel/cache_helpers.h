/*
 * Copyright (c) 2017, Linaro Limited
 * All rights reserved.
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

#ifndef __KERNEL_CACHE_HELPERS_H
#define __KERNEL_CACHE_HELPERS_H

#ifndef ASM
#include <types_ext.h>
#endif

/* Data Cache set/way op type defines */
#define DCACHE_OP_INV		0x0
#define DCACHE_OP_CLEAN_INV	0x1
#define DCACHE_OP_CLEAN		0x2

#ifndef ASM
void dcache_cleaninv_range(void *addr, size_t size);
void dcache_clean_range(void *addr, size_t size);
void dcache_inv_range(void *addr, size_t size);

void icache_inv_all(void);
void icache_inv_range(void *addr, size_t size);

void dcache_op_louis(unsigned long op_type);
void dcache_op_all(unsigned long op_type);

void dcache_op_level1(unsigned long op_type);
void dcache_op_level2(unsigned long op_type);
void dcache_op_level3(unsigned long op_type);
#endif /*!ASM*/

#endif /*__KERNEL_CACHE_HELPERS_H*/
