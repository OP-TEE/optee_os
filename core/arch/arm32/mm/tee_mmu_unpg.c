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

#include <arm32.h>
#include <mm/tee_mmu_unpg.h>
#include <mm/tee_mmu_defs.h>
#include <mm/core_mmu.h>

void tee_mmu_get_map(struct tee_mmu_mapping *map)
{
	if (map == NULL)
		return;

	map->ttbr0 = read_ttbr0();
	map->ctxid = read_contextidr();
}

void tee_mmu_set_map(struct tee_mmu_mapping *map)
{
	if (map == NULL)
		tee_mmu_switch(read_ttbr1(), 0);
	else
		tee_mmu_switch(map->ttbr0, map->ctxid);

	core_tlb_maintenance(TLBINV_UNIFIEDTLB, 0);
}

void tee_mmu_switch(uint32_t ttbr0_base, uint32_t ctxid)
{
	uint32_t cpsr = read_cpsr();

	/* Disable interrupts */
	write_cpsr(cpsr | CPSR_FIA);

	/*
	 * Update the reserved Context ID and TTBR0
	 */

	dsb();	/* ARM erratum 754322 */
	write_contextidr(0);
	isb();

	write_ttbr0(ttbr0_base);
	isb();

	write_contextidr(ctxid & 0xff);
	isb();

	/* Restore interrupts */
	write_cpsr(cpsr);
}
