/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
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

#include <mm/tee_mm_unpg.h>
#include <compiler.h>

/* Physical Public DDR pool */
tee_mm_pool_t tee_mm_pub_ddr __data; /* XXX __data is a workaround */

/* Physical Secure DDR pool */
tee_mm_pool_t tee_mm_sec_ddr __data; /* XXX __data is a workaround */

/* Virtual eSRAM pool */
tee_mm_pool_t tee_mm_vcore __data; /* XXX __data is a workaround */

tee_mm_entry_t *tee_mm_find(const tee_mm_pool_t *pool, uint32_t addr)
{
	tee_mm_entry_t *entry = pool->entry;
	uint16_t offset = (addr - pool->lo) >> pool->shift;

	if (addr > pool->hi || addr < pool->lo)
		return NULL;

	while (entry->next != NULL) {
		entry = entry->next;

		if ((offset >= entry->offset) &&
		    (offset < (entry->offset + entry->size))) {
			return entry;
		}
	}

	return NULL;
}

uintptr_t tee_mm_get_smem(const tee_mm_entry_t *mm)
{
	return (mm->offset << mm->pool->shift) + mm->pool->lo;
}
