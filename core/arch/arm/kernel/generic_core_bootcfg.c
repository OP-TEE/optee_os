/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * Copyright (c) 2015-2016, Renesas Electronics Corporation
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

/* Define the platform's memory layout. */
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
#ifdef TZSRAM_BASE
	MEMACCESS_AREA(TZSRAM_BASE, TZSRAM_SIZE),
#endif
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

/* Wrapper for the platform specific pbuf_is() service. */
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
		EMSG("Unexpected request: attr=%X", attr);
		return false;
	}
}

/* Platform-specific memory layout provided to TEE core. */
static struct map_area bootcfg_memory_map[] = {
	/* TEE core execution RAM. */
	{
	 .type = MEM_AREA_TEE_RAM,
	 .pa = CFG_TEE_RAM_START, .size = CFG_TEE_RAM_PH_SIZE,
#ifdef CFG_WITH_PAGER
	 .region_size = SMALL_PAGE_SIZE,
#endif
	 .cached = true, .secure = true, .rw = true, .exec = true,
	 },

	/* TEE core TA load/exec RAM: secure, user exec only. */
	{
	 .type = MEM_AREA_TA_RAM,
	 .pa = CFG_TA_RAM_START, .size = CFG_TA_RAM_SIZE,
	 .cached = true, .secure = true, .rw = true, .exec = false,
	 },

	/* TEE core public RAM: non-secure, non-exec. */
	{
	 .type = MEM_AREA_NSEC_SHM,
	 .pa = CFG_SHMEM_START, .size = CFG_SHMEM_SIZE,
	 .cached = true, .secure = false, .rw = true, .exec = false,
	 },

	{
	 .type = DEVICE0_TYPE,
	 .pa = DEVICE0_PA_BASE, .size = DEVICE0_SIZE,
	 .va = DEVICE0_VA_BASE,
	 .device = true, .secure = true, .rw = true,
	 },
#ifdef DEVICE1_PA_BASE
	{
	 .type = DEVICE1_TYPE,
	 .pa = DEVICE1_PA_BASE, .size = DEVICE1_SIZE,
	 .va = DEVICE1_VA_BASE,
	 .device = true, .secure = true, .rw = true,
	 },
#endif
#ifdef DEVICE2_PA_BASE
	{
	 .type = DEVICE2_TYPE,
	 .pa = DEVICE2_PA_BASE, .size = DEVICE2_SIZE,
	 .va = DEVICE2_VA_BASE,
	 .device = true, .secure = true, .rw = true,
	 },
#endif
#ifdef DEVICE3_PA_BASE
	{
	 .type = DEVICE3_TYPE,
	 .pa = DEVICE3_PA_BASE, .size = DEVICE3_SIZE,
	 .va = DEVICE3_VA_BASE,
	 .device = true, .secure = true, .rw = true,
	 },
#endif
#ifdef DEVICE4_PA_BASE
	{
	 .type = DEVICE4_TYPE,
	 .pa = DEVICE4_PA_BASE, .size = DEVICE4_SIZE,
	 .va = DEVICE4_VA_BASE,
	 .device = true, .secure = true, .rw = true,
	 },
#endif
#ifdef DEVICE5_PA_BASE
	{
	 .type = DEVICE5_TYPE,
	 .pa = DEVICE5_PA_BASE, .size = DEVICE5_SIZE,
	 .va = DEVICE5_VA_BASE,
	 .device = true, .secure = true, .rw = true,
	 },
#endif
#ifdef DEVICE6_PA_BASE
	{
	 .type = DEVICE6_TYPE,
	 .pa = DEVICE6_PA_BASE, .size = DEVICE6_SIZE,
	 .va = DEVICE6_VA_BASE,
	 .device = true, .secure = true, .rw = true,
	 },
#endif
#ifdef MEMORY1_BASE
	{
	 .type = MEMORY1_TYPE,
	 .pa = MEMORY1_BASE, .size = MEMORY1_SIZE,
	 .secure = MEMORY1_SECURE, .cached = MEMORY1_CACHED,
	 .device = MEMORY1_DEVICE, .rw = MEMORY1_RW, .exec = MEMORY1_EXEC,
	 },
#endif
#ifdef MEMORY2_BASE
	{
	 .type = MEMORY2_TYPE,
	 .pa = MEMORY2_BASE, .size = MEMORY2_SIZE,
	 .secure = MEMORY2_SECURE, .cached = MEMORY2_CACHED,
	 .device = MEMORY2_DEVICE, .rw = MEMORY2_RW, .exec = MEMORY2_EXEC,
	 },
#endif
#ifdef MEMORY3_BASE
	{
	 .type = MEMORY3_TYPE,
	 .pa = MEMORY3_BASE, .size = MEMORY3_SIZE,
	 .secure = MEMORY3_SECURE, .cached = MEMORY3_CACHED,
	 .device = MEMORY3_DEVICE, .rw = MEMORY3_RW, .exec = MEMORY3_EXEC,
	 },
#endif
#ifdef MEMORY4_BASE
	{
	 .type = MEMORY4_TYPE,
	 .pa = MEMORY4_BASE, .size = MEMORY4_SIZE,
	 .secure = MEMORY4_SECURE, .cached = MEMORY4_CACHED,
	 .device = MEMORY4_DEVICE, .rw = MEMORY4_RW, .exec = MEMORY4_EXEC,
	 },
#endif
#ifdef MEMORY5_BASE
	{
	 .type = MEMORY5_TYPE,
	 .pa = MEMORY5_BASE, .size = MEMORY5_SIZE,
	 .secure = MEMORY5_SECURE, .cached = MEMORY5_CACHED,
	 .device = MEMORY5_DEVICE, .rw = MEMORY5_RW, .exec = MEMORY5_EXEC,
	 },
#endif
#ifdef MEMORY6_BASE
	{
	 .type = MEMORY6_TYPE,
	 .pa = MEMORY6_BASE, .size = MEMORY6_SIZE,
	 .secure = MEMORY6_SECURE, .cached = MEMORY6_CACHED,
	 .device = MEMORY6_DEVICE, .rw = MEMORY6_RW, .exec = MEMORY6_EXEC,
	 },
#endif
	{.type = MEM_AREA_NOTYPE}
};

/* Return the platform specific pbuf_is(). */
unsigned long bootcfg_get_pbuf_is_handler(void)
{
	return (unsigned long)pbuf_is;
}

/*
 * This routine is called when MMU and core memory management are not
 * initialized.
 */
struct map_area *bootcfg_get_memory(void)
{
	struct map_area *map;
	size_t n;

	for (n = 0; n < ARRAY_SIZE(secure_only); n++) {
		if (pbuf_intersects(nsec_shared, secure_only[n].paddr,
				    secure_only[n].size)) {
			EMSG("Invalid memory access configuration: sec/nsec");
			return NULL;
		}
	}

	/* Overlapping will be tested later */
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
			/* Other mapped areas are not checked. */
			break;
		}
		map++;
	}

	return bootcfg_memory_map;
}
