/*
 * Copyright (c) 2014, Allwinner Technology Co., Ltd.
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
};

static struct memaccess_area secure_only =
MEMACCESS_AREA(CFG_DDR_ARMTZ_ONLY_START, CFG_DDR_ARMTZ_ONLY_SIZE);

static struct memaccess_area nsec_shared =
MEMACCESS_AREA(CFG_DDR_ARM_ARMTZ_START, CFG_DDR_ARM_ARMTZ_SIZE);

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

static struct map_area bootcfg_memory[] = {
	{ /* teecore execution RAM */
	 .type = MEM_AREA_TEE_RAM,
	 .pa = CFG_TEE_RAM_START, .size = CFG_TEE_RAM_SIZE,
	 .cached = true, .secure = true, .rw = true, .exec = true,
	 },

	{ /* teecore TA load/exec RAM - Secure, exec user only! */
	 .type = MEM_AREA_TA_RAM,
	 .pa = CFG_TA_RAM_START, .size = CFG_TA_RAM_SIZE,
	 .cached = true, .secure = true, .rw = true, .exec = false,
	 },

	{ /* teecore public RAM - NonSecure, non-exec. */
	 .type = MEM_AREA_NSEC_SHM,
	 .pa = CFG_PUB_RAM_START, .size = CFG_PUB_RAM_SIZE,
	 .cached = true, .secure = false, .rw = true, .exec = false,
	 },

	{ /* AHB0 devices */
	 .type = MEM_AREA_IO_NSEC,
	 .pa = 0x01400000 & ~CORE_MMU_DEVICE_MASK,
	 .size = ROUNDUP(0x00900000, CORE_MMU_DEVICE_SIZE),
	 .device = true, .secure = true, .rw = true,
	 },

	{ /* AHB1 devices */
	 .type = MEM_AREA_IO_NSEC,
	 .pa = (0x00800000) & ~CORE_MMU_DEVICE_MASK,
	 .size = ROUNDUP(0x00300000, CORE_MMU_DEVICE_SIZE),
	 .device = true, .secure = true, .rw = true,
	 },
	{ /* AHB2 devices */
	 .type = MEM_AREA_IO_NSEC,
	 .pa = (0x03000000) & ~CORE_MMU_DEVICE_MASK,
	 .size = ROUNDUP(0x01000000, CORE_MMU_DEVICE_SIZE),
	 .device = true, .secure = true, .rw = true,
	 },
	{ /* AHBS devices */
	 .type = MEM_AREA_IO_NSEC,
	 .pa = (0x06000000) & ~CORE_MMU_DEVICE_MASK,
	 .size = ROUNDUP(0x02200000, CORE_MMU_DEVICE_SIZE),
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
	struct map_area *ret = bootcfg_memory;
	
	/* check defined memory access layout */
	a = (struct memaccess_area *)&secure_only;
	a2 = (struct memaccess_area *)&nsec_shared;
	if (core_is_buffer_intersect(a->paddr, a->size, a2->paddr, a2->size)) {
		EMSG("invalid memory access configuration: sec/nsec");
		return NULL;
	}

	/* check defined mapping (overlapping will be tested later) */
	map = bootcfg_memory;
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
				EMSG("TA_RAM does not fit in secure_only");
				ret = NULL;
			}
			break;
		case MEM_AREA_NSEC_SHM:
			a = (struct memaccess_area *)&nsec_shared;
			if (!core_is_buffer_inside(map->pa, map->size,
						a->paddr, a->size)) {
				EMSG("NSEC_RAM does not fit in nsec_shared");
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

