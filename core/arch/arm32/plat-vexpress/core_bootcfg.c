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
#include <kernel/tee_core_trace.h>

#ifndef CFG_DDR_TEETZ_RESERVED_START
#error "TEETZ reserved DDR start address undef: CFG_DDR_TEETZ_RESERVED_START"
#endif
#ifndef CFG_DDR_TEETZ_RESERVED_SIZE
#error "TEETZ reserved DDR siez undefined: CFG_DDR_TEETZ_RESERVED_SIZE"
#endif

/*
 * TEE/TZ RAM layout:
 *
 *  +-----------------------------------------+  <- CFG_DDR_TEETZ_RESERVED_START
 *  | TEETZ private RAM  |  TEE_RAM           |   ^
 *  |                    +--------------------+   |
 *  |                    |  TA_RAM            |   |
 *  +-----------------------------------------+   | CFG_DDR_TEETZ_RESERVED_SIZE
 *  |                    |      teecore alloc |   |
 *  |  TEE/TZ and NSec   |  PUB_RAM   --------|   |
 *  |   shared memory    |         NSec alloc |   |
 *  +-----------------------------------------+   v
 *
 *  TEE_RAM : 1MByte
 *  PUB_RAM : 1MByte
 *  TA_RAM  : all what is left (at least 2MByte !)
 */

/* define the several memory area sizes */
#if (CFG_DDR_TEETZ_RESERVED_SIZE < (4 * 1024 * 1024))
#error "Invalid CFG_DDR_TEETZ_RESERVED_SIZE: at least 4MB expected"
#endif

#if PLATFORM_FLAVOR_IS(fvp)

#define CFG_PUB_RAM_SIZE		CFG_SHMEM_SIZE
#define CFG_TEE_RAM_SIZE		(1 * 1024 * 1024)
#define CFG_TA_RAM_SIZE			(CFG_DDR_TEETZ_RESERVED_SIZE - \
					CFG_TEE_RAM_SIZE - CFG_PUB_RAM_SIZE)

/* define the secure/unsecure memory areas */
#define CFG_DDR_ARMTZ_ONLY_START	(CFG_DDR_TEETZ_RESERVED_START)
#define CFG_DDR_ARMTZ_ONLY_SIZE		(CFG_TEE_RAM_SIZE + CFG_TA_RAM_SIZE)

/* define the memory areas (TEE_RAM must start at reserved DDR start addr */
#define CFG_TEE_RAM_START		(CFG_DDR_ARMTZ_ONLY_START)
#define CFG_TA_RAM_START		(CFG_TEE_RAM_START + CFG_TEE_RAM_SIZE)

#define CFG_PUB_RAM_START		CFG_SHMEM_START



#elif PLATFORM_FLAVOR_IS(qemu)

#define CFG_PUB_RAM_SIZE		(1 * 1024 * 1024)
#define CFG_TEE_RAM_SIZE		(1 * 1024 * 1024)
#define CFG_TA_RAM_SIZE			(CFG_DDR_TEETZ_RESERVED_SIZE - \
					CFG_TEE_RAM_SIZE - CFG_PUB_RAM_SIZE)

/* define the secure/unsecure memory areas */
#define CFG_DDR_ARMTZ_ONLY_START	(CFG_DDR_TEETZ_RESERVED_START)
#define CFG_DDR_ARMTZ_ONLY_SIZE		(CFG_TEE_RAM_SIZE + CFG_TA_RAM_SIZE)

#define CFG_DDR_ARM_ARMTZ_START		\
			(CFG_DDR_ARMTZ_ONLY_START + CFG_DDR_ARMTZ_ONLY_SIZE)
#define CFG_DDR_ARM_ARMTZ_SIZE		(CFG_PUB_RAM_SIZE)

/* define the memory areas (TEE_RAM must start at reserved DDR start addr */
#define CFG_TEE_RAM_START		(CFG_DDR_ARMTZ_ONLY_START)
#define CFG_TA_RAM_START		(CFG_TEE_RAM_START + CFG_TEE_RAM_SIZE)
#define CFG_PUB_RAM_START		(CFG_TA_RAM_START + CFG_TA_RAM_SIZE)

#endif

/*
 * define the platform memory Secure layout
 */
struct memaccess_area {
	unsigned long paddr;
	size_t size;
};
#define MEMACCESS_AREA(a, s) { .paddr = a, .size = s }

static struct memaccess_area ddr[] = {
	MEMACCESS_AREA(CFG_DDR_START, CFG_DDR_SIZE),
#ifdef CFG_DDR1_START
	MEMACCESS_AREA(CFG_DDR1_START, CFG_DDR1_SIZE),
#endif
};

static struct memaccess_area secure_only =
MEMACCESS_AREA(CFG_DDR_ARMTZ_ONLY_START, CFG_DDR_ARMTZ_ONLY_SIZE);

static struct memaccess_area nsec_shared =
#if PLATFORM_FLAVOR_IS(fvp)
MEMACCESS_AREA(CFG_PUB_RAM_START, CFG_PUB_RAM_SIZE);
#elif PLATFORM_FLAVOR_IS(qemu)
MEMACCESS_AREA(CFG_DDR_ARM_ARMTZ_START, CFG_DDR_ARM_ARMTZ_SIZE);
#endif

/*
 * buf_inside_area - return true is buffer fits in target area
 *
 * @bp: buffer physical address
 * @bs: buffer size in bytes
 * @ap: memory physical address
 * @as: memory size in bytes
 */
static bool buf_inside_area(unsigned long bp, size_t bs, unsigned long ap,
			    size_t as)
{
	/* not malformed input data */
	if (((bp + bs - 1) < bp) ||
	    ((ap + as - 1) < ap) ||
	    (bs == 0) ||
	    (as == 0))
		return false;

	if ((bp < ap) || ((bp + bs) > (ap + as)))
		return false;

	return true;
}

/*
 * buf_overlaps_area - return true is buffer overlaps target area
 *
 * @bp: buffer physical address
 * @bs: buffer size in bytes
 * @ap: memory physical address
 * @as: memory size in bytes
 */
static bool buf_overlaps_area(unsigned long bp, size_t bs, unsigned long ap,
			      size_t as)
{
	/* not malformed input data */
	if (((bp + bs - 1) < bp) ||
	    ((ap + as - 1) < ap) ||
	    (bs == 0) ||
	    (as == 0))
		return false;

	if ((bp < ap) || ((bp + bs) > ap))
		return false;

	if ((bp >= ap) || (bp < (ap + as)))
		return false;

	return true;
}

static bool pbuf_is_ddr(unsigned long paddr, size_t size)
{
	int i = sizeof(ddr) / sizeof(*ddr);

	while (i--) {
		if (buf_inside_area(paddr, size, ddr[i].paddr, ddr[i].size))
			return true;
	}
	return false;
}

static bool pbuf_is_multipurpose(unsigned long paddr, size_t size)
{
	if (buf_overlaps_area(paddr, size, secure_only.paddr, secure_only.size))
		return false;
	if (buf_overlaps_area(paddr, size, nsec_shared.paddr, nsec_shared.size))
		return false;
	if (buf_overlaps_area(paddr, size, nsec_shared.paddr, nsec_shared.size))
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
		if (buf_inside_area
		    (paddr, size, secure_only.paddr, secure_only.size))
			return true;
		return false;

	case CORE_MEM_NON_SEC:
		return buf_inside_area(paddr, size, nsec_shared.paddr,
				       nsec_shared.size);

	case CORE_MEM_MULTPURPOSE:
		return pbuf_is_multipurpose(paddr, size);

	case CORE_MEM_EXTRAM:
		return pbuf_is_ddr(paddr, size);

	default:
		EMSG("unpexted request: attr=%X", attr);
		return false;
	}
}

static struct map_area bootcfg_stih416_memory[] = {
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
	 .pa = CFG_PUB_RAM_START, .size = SECTION_SIZE,
	 .cached = true, .secure = false, .rw = true, .exec = false,
	 },

	{	/* UART */
	 .type = MEM_AREA_IO_NSEC,
	 .pa = UART0_BASE & ~SECTION_MASK, .size = SECTION_SIZE,
	 .device = true, .secure = false, .rw = true,
	 },

	{	/* GIC */
	 .type = MEM_AREA_IO_SEC,
	 .pa = GIC_BASE & ~SECTION_MASK, .size = SECTION_SIZE,
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
	struct map_area *ret = bootcfg_stih416_memory;

	/* check defined memory access layout */
	a = (struct memaccess_area *)&secure_only;
	a2 = (struct memaccess_area *)&nsec_shared;
	if (buf_overlaps_area(a->paddr, a->size, a2->paddr, a2->size)) {
		EMSG("invalid memory access configuration: sec/nsec");
		ret = NULL;
	}
	if (ret == NULL)
		return ret;

	/* check defined mapping (overlapping will be tested later) */
	map = bootcfg_stih416_memory;
	while (map->type != MEM_AREA_NOTYPE) {
		switch (map->type) {
		case MEM_AREA_TEE_RAM:
			a = (struct memaccess_area *)&secure_only;
			if (buf_inside_area
			    (map->pa, map->size, a->paddr, a->size) == false) {
				EMSG("TEE_RAM does not fit in secure_only");
				ret = NULL;
			}
			break;
		case MEM_AREA_TA_RAM:
			a = (struct memaccess_area *)&secure_only;
			if (buf_inside_area
			    (map->pa, map->size, a->paddr, a->size) == false) {
				EMSG("TEE_RAM does not fit in secure_only");
				ret = NULL;
			}
			break;
#if PLATFORM_FLAVOR_IS(qemu)
		case MEM_AREA_NSEC_SHM:
			a = (struct memaccess_area *)&nsec_shared;
			if (buf_inside_area
			    (map->pa, map->size, a->paddr, a->size) == false) {
				EMSG("TEE_RAM does not fit in secure_only");
				ret = NULL;
			}
			break;
#endif
		default:
			/* other mapped areas are not checked */
			break;
		}
		map++;
	}

	return ret;
}
