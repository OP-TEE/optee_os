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
#include <platform_config.h>
#include <mm/core_mmu.h>
#include <mm/core_memprot.h>
#include <trace.h>
#include <kernel/tee_misc.h>

/*
 * define the platform memory Secure layout
 */
struct memaccess_area {
	unsigned long paddr;
	size_t size;
};
#define MEMACCESS_AREA(a, s) { .paddr = a, .size = s }

static struct memaccess_area ddr[] = {
	MEMACCESS_AREA(DRAM0_BASE, DRAM0_SIZE),
#ifdef DRAM1_BASE
	MEMACCESS_AREA(DRAM1_BASE, DRAM1_SIZE),
#endif
};

static struct memaccess_area secure_only =
MEMACCESS_AREA(TZDRAM_BASE, TZDRAM_SIZE);

static struct memaccess_area nsec_shared =
MEMACCESS_AREA(CFG_SHMEM_START, CFG_SHMEM_SIZE);


/* pbuf_is_ddr - return true is buffer is inside the DDR */
static bool pbuf_is_ddr(unsigned long paddr, size_t size)
{
	int i = sizeof(ddr) / sizeof(*ddr);

	while (i--) {
		if (core_is_buffer_inside(paddr, size,
					ddr[i].paddr, ddr[i].size))
			return true;
	}
	return false;
}

/*
 * pbuf_is_multipurpose - return true is buffer is inside unsafe DDR
 *
 * Unsafe DDR (or multipurpose DDR) is DDR that is under a firewalling
 * reconfigured at run-time: there is no static information that can
 * tell wether this RAM is tagged secured or not.
 */
static bool pbuf_is_multipurpose(unsigned long paddr, size_t size)
{
	if (core_is_buffer_intersect(paddr, size,
				     secure_only.paddr, secure_only.size))
		return false;
	if (core_is_buffer_intersect(paddr, size,
				     nsec_shared.paddr, nsec_shared.size))
		return false;

	return pbuf_is_ddr(paddr, size);
}

/*
 * Wrapper for the platform specific pbuf_is() service.
 */
static bool pbuf_is(enum buf_is_attr attr, unsigned long paddr, size_t size)
{
	switch (attr) {
	case CORE_MEM_SEC:
		return core_is_buffer_inside(paddr, size,
					secure_only.paddr, secure_only.size);

	case CORE_MEM_NON_SEC:
		return core_is_buffer_inside(paddr, size,
					nsec_shared.paddr, nsec_shared.size);

	case CORE_MEM_MULTPURPOSE:
		return pbuf_is_multipurpose(paddr, size);

	case CORE_MEM_EXTRAM:
		return pbuf_is_ddr(paddr, size);

	default:
		EMSG("unpexted request: attr=%X", attr);
		return false;
	}
}

/* platform specific memory layout provided to teecore */
static struct map_area bootcfg_memory_map[] = {
	{	/* teecore execution RAM */
	 .type = MEM_AREA_TEE_RAM,
	 .pa = CFG_TEE_RAM_START, .size = CFG_TEE_RAM_SIZE,
	 .cached = true, .secure = true, .rw = true, .exec = true,
	 },

	{	/* teecore TA load/exec RAM - Secure, exec user only! */
	 .type = MEM_AREA_TA_RAM,
	 .pa = CFG_TA_RAM_START, .size = CFG_TA_RAM_SIZE,
	 .cached = true, .secure = true, .rw = true, .exec = false,
	 },

	{	/* teecore public RAM - NonSecure, non-exec. */
	 .type = MEM_AREA_NSEC_SHM,
	 .pa = CFG_SHMEM_START, .size = CFG_SHMEM_SIZE,
	 .cached = true, .secure = false, .rw = true, .exec = false,
	 },

	{	/* CPU mem map HW registers */
	 .type = MEM_AREA_IO_NSEC,
	 .pa = CPU_IOMEM_BASE & ~SECTION_MASK, .size = SECTION_SIZE,
	 .device = true, .secure = true, .rw = true,
	 },

	{	/* ASC IP for UART HW tracing */
	 .type = MEM_AREA_IO_NSEC,
	 .pa = UART_CONSOLE_BASE & ~SECTION_MASK, .size = SECTION_SIZE,
	 .device = true, .secure = false, .rw = true,
	 },

	{	/* RNG IP for some random support */
	 .type = MEM_AREA_IO_SEC,
	 .pa = RNG_BASE & ~SECTION_MASK, .size = SECTION_SIZE,
	 .device = true, .secure = true, .rw = true,
	 },

	{.type = MEM_AREA_NOTYPE}
};

/*
 * bootcfg_get_pbuf_is_handler - return the platform specfic pbuf_is
 */
unsigned long bootcfg_get_pbuf_is_handler(void)
{
	return (unsigned long)pbuf_is;
}

/*
 * This routine is called while MMU and core memory management are not init.
 */
struct map_area *bootcfg_get_memory(void)
{
	struct map_area *map;
	struct memaccess_area *a, *a2;
	struct map_area *ret = bootcfg_memory_map;

	/* check defined memory access layout */
	a = (struct memaccess_area *)&secure_only;
	a2 = (struct memaccess_area *)&nsec_shared;
	if (core_is_buffer_intersect(a->paddr, a->size, a2->paddr, a2->size)) {
		EMSG("invalid memory access configuration: sec/nsec");
		ret = NULL;
	}
	if (ret == NULL)
		return ret;

	/* check defined mapping (overlapping will be tested later) */
	map = bootcfg_memory_map;
	while (map->type != MEM_AREA_NOTYPE) {
		switch (map->type) {
		case MEM_AREA_TEE_RAM:
			a = (struct memaccess_area *)&secure_only;
			if (!core_is_buffer_inside(map->pa, map->size,
						a->paddr, a->size)) {
				EMSG("TEE_RAM does not fit in secure_only");
				ret = NULL;
			}
			break;
		case MEM_AREA_TA_RAM:
			a = (struct memaccess_area *)&secure_only;
			if (!core_is_buffer_inside(map->pa, map->size,
						a->paddr, a->size)) {
				EMSG("TEE_RAM does not fit in secure_only");
				ret = NULL;
			}
			break;
		case MEM_AREA_NSEC_SHM:
			a = (struct memaccess_area *)&nsec_shared;
			if (!core_is_buffer_inside(map->pa, map->size,
						a->paddr, a->size)) {
				EMSG("TEE_RAM does not fit in secure_only");
				ret = NULL;
			}
			break;
		default:
			/* other mapped areas are not checked */
			break;
		}
		map++;
	}

	return ret;
}
