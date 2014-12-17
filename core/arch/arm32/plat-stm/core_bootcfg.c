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
#include <util.h>
#include <kernel/tee_misc.h>
#include <trace.h>

/*
 * define the platform memory Secure layout
 */
struct memaccess_area {
	paddr_t paddr;
	size_t size;
};
#define MEMACCESS_AREA(a, s) { .paddr = a, .size = s }

static struct memaccess_area ddr[] = {
	MEMACCESS_AREA(DRAM0_BASE, DRAM0_SIZE),
#ifdef DRAM1_BASE
	MEMACCESS_AREA(DRAM1_BASE, DRAM1_SIZE),
#endif
};

static struct memaccess_area secure_only[] = {
	MEMACCESS_AREA(TZDRAM_BASE, TZDRAM_SIZE),
};

static struct memaccess_area nsec_shared[] = {
	MEMACCESS_AREA(CFG_SHMEM_START, CFG_SHMEM_SIZE),
};

static bool _pbuf_intersects(struct memaccess_area *a, size_t alen,
			     paddr_t pa, size_t size)
{
	size_t n;

	for (n = 0; n < alen; n++)
		if (core_is_buffer_intersect(pa, size, a[n].paddr, a[n].size))
			return true;
	return false;
}
#define pbuf_intersects(a, pa, size) \
	_pbuf_intersects((a), ARRAY_SIZE(a), (pa), (size))

static bool _pbuf_is_inside(struct memaccess_area *a, size_t alen,
			    paddr_t pa, size_t size)
{
	size_t n;

	for (n = 0; n < alen; n++)
		if (core_is_buffer_inside(pa, size, a[n].paddr, a[n].size))
			return true;
	return false;
}
#define pbuf_is_inside(a, pa, size) \
	_pbuf_is_inside((a), ARRAY_SIZE(a), (pa), (size))

static bool pbuf_is_multipurpose(paddr_t paddr, size_t size)
{
	if (pbuf_intersects(secure_only, paddr, size))
		return false;
	if (pbuf_intersects(nsec_shared, paddr, size))
		return false;

	return pbuf_is_inside(ddr, paddr, size);
}

/*
 * Wrapper for the platform specific pbuf_is() service.
 */
static bool pbuf_is(enum buf_is_attr attr, paddr_t paddr, size_t size)
{
	switch (attr) {
	case CORE_MEM_SEC:
		return pbuf_is_inside(secure_only, paddr, size);

	case CORE_MEM_NON_SEC:
		return pbuf_is_inside(nsec_shared, paddr, size);

	case CORE_MEM_MULTPURPOSE:
		return pbuf_is_multipurpose(paddr, size);

	case CORE_MEM_EXTRAM:
		return pbuf_is_inside(ddr, paddr, size);

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
	size_t n;

	/* check defined memory access layout */
	for (n = 0; n < ARRAY_SIZE(secure_only); n++) {
		if (pbuf_intersects(nsec_shared, secure_only[n].paddr,
				    secure_only[n].size)) {
			EMSG("invalid memory access configuration: sec/nsec");
			return NULL;
		}
	}

	/* check defined mapping (overlapping will be tested later) */
	map = bootcfg_memory_map;
	while (map->type != MEM_AREA_NOTYPE) {
		switch (map->type) {
		case MEM_AREA_TEE_RAM:
			if (!pbuf_is_inside(secure_only, map->pa, map->size)) {
				EMSG("TEE_RAM does not fit in secure_only");
				return NULL;
			}
			break;
		case MEM_AREA_TA_RAM:
			if (!pbuf_is_inside(secure_only, map->pa, map->size)) {
				EMSG("TA_RAM does not fit in secure_only");
				return NULL;
			}
			break;
		case MEM_AREA_NSEC_SHM:
			if (!pbuf_is_inside(nsec_shared, map->pa, map->size)) {
				EMSG("NSEC_SHM does not fit in nsec_shared");
				return NULL;
			}
			break;
		default:
			/* other mapped areas are not checked */
			break;
		}
		map++;
	}

	return bootcfg_memory_map;
}
