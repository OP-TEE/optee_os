// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2017 NXP
 * All rights reserved.
 *
 * Peng Fan <peng.fan@nxp.com>
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

#include <assert.h>
#include <drivers/tzc380.h>
#include <io.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <stddef.h>
#include <trace.h>
#include <util.h>

/*
 * Implementation defined values used to validate inputs later.
 * Filters : max of 4 ; 0 to 3
 * Regions : max of 9 ; 0 to 8
 * Address width : Values between 32 to 64
 */
struct tzc_instance {
	vaddr_t base;
	uint8_t addr_width;
	uint8_t num_regions;
};

static struct tzc_instance tzc;

static uint32_t tzc_read_build_config(vaddr_t base)
{
	return io_read32(base + BUILD_CONFIG_OFF);
}

static void tzc_write_action(vaddr_t base, enum tzc_action action)
{
	io_write32(base + ACTION_OFF, action);
}

static void tzc_write_region_base_low(vaddr_t base, uint32_t region,
				      uint32_t val)
{
	io_write32(base + REGION_SETUP_LOW_OFF(region), val);
}

static void tzc_write_region_base_high(vaddr_t base, uint32_t region,
				       uint32_t val)
{
	io_write32(base + REGION_SETUP_HIGH_OFF(region), val);
}

static uint32_t tzc_read_region_attributes(vaddr_t base, uint32_t region)
{
	return io_read32(base + REGION_ATTRIBUTES_OFF(region));
}

static void tzc_write_region_attributes(vaddr_t base, uint32_t region,
					uint32_t val)
{
	io_write32(base + REGION_ATTRIBUTES_OFF(region), val);
}

void tzc_init(vaddr_t base)
{
	uint32_t tzc_build;

	assert(base);
	tzc.base = base;

	/* Save values we will use later. */
	tzc_build = tzc_read_build_config(tzc.base);
	tzc.addr_width  = ((tzc_build >> BUILD_CONFIG_AW_SHIFT) &
			   BUILD_CONFIG_AW_MASK) + 1;
	tzc.num_regions = ((tzc_build >> BUILD_CONFIG_NR_SHIFT) &
			   BUILD_CONFIG_NR_MASK) + 1;
}

/*
 * There are two modes of operation for the region security
 * permissions, with or without security inversion.
 * Check TZC380 "2.2.5 Region security permissions" for
 * more details.
 */
void tzc_security_inversion_en(vaddr_t base)
{
	io_write32(base + SECURITY_INV_EN_OFF, 1);
}

/*
 * Enable a single region. Sometimes we could not use tzc_configure_region
 * to enable the region, when security inversion is on.
 * When need security inversion, we need to first configure
 * region address and attribute, then configure security inversion,
 * then enable the regions.
 */
void tzc_region_enable(uint8_t region)
{
	uint32_t val;

	val = tzc_read_region_attributes(tzc.base, region);
	val |= TZC_ATTR_REGION_EN_MASK;
	tzc_write_region_attributes(tzc.base, region, val);
}

/*
 * Dump info when TZC380 catchs an unallowed access with TZC
 * interrupt enabled.
 */
void tzc_fail_dump(void)
{
	vaddr_t base __maybe_unused = core_mmu_get_va(tzc.base,
						      MEM_AREA_IO_SEC);

	EMSG("Fail address Low 0x%" PRIx32,
	     io_read32(base + FAIL_ADDRESS_LOW_OFF));
	EMSG("Fail address High 0x%" PRIx32,
	     io_read32(base + FAIL_ADDRESS_HIGH_OFF));
	EMSG("Fail Control 0x%" PRIx32, io_read32(base + FAIL_CONTROL_OFF));
	EMSG("Fail Id 0x%" PRIx32, io_read32(base + FAIL_ID));
}

void tzc_int_clear(void)
{
	vaddr_t base = core_mmu_get_va(tzc.base, MEM_AREA_IO_SEC);

	io_write32(base + INT_CLEAR, 0);
}

static uint32_t addr_low(vaddr_t addr)
{
	return (uint32_t)addr;
}

static uint32_t addr_high(vaddr_t addr __maybe_unused)
{
#if (UINTPTR_MAX == UINT64_MAX)
	return addr >> 32;
#else
	return 0;
#endif
}


/*
 * `tzc_configure_region` is used to program regions into the TrustZone
 * controller.
 */
void tzc_configure_region(uint8_t region, vaddr_t region_base, uint32_t attr)
{
	assert(tzc.base);

	assert(region < tzc.num_regions);

	/*
	 * For region 0, this high/low/size/en field is Read Only (RO).
	 * So should not configure those field for region 0.
	 */
	if (region) {
		tzc_write_region_base_low(tzc.base, region,
					  addr_low(region_base));
		tzc_write_region_base_high(tzc.base, region,
					   addr_high(region_base));
		tzc_write_region_attributes(tzc.base, region, attr);
	} else {
		tzc_write_region_attributes(tzc.base, region,
					    attr & TZC_ATTR_SP_MASK);
	}
}

void tzc_set_action(enum tzc_action action)
{
	assert(tzc.base);

	/*
	 * - Currently no handler is provided to trap an error via interrupt
	 *   or exception.
	 * - The interrupt action has not been tested.
	 */
	tzc_write_action(tzc.base, action);
}

#if TRACE_LEVEL >= TRACE_DEBUG

static uint32_t tzc_read_region_base_low(vaddr_t base, uint32_t region)
{
	return io_read32(base + REGION_SETUP_LOW_OFF(region));
}

static uint32_t tzc_read_region_base_high(vaddr_t base, uint32_t region)
{
	return io_read32(base + REGION_SETUP_HIGH_OFF(region));
}

#define	REGION_MAX	16
void tzc_dump_state(void)
{
	uint32_t n;
	uint32_t temp_32reg, temp_32reg_h;

	DMSG("enter");
	DMSG("security_inversion_en %x\n",
	     io_read32(tzc.base + SECURITY_INV_EN_OFF));
	for (n = 0; n <= REGION_MAX; n++) {
		temp_32reg = tzc_read_region_attributes(tzc.base, n);
		if (!(temp_32reg & TZC_ATTR_REGION_EN_MASK))
			continue;

		DMSG("\n");
		DMSG("region %d", n);
		temp_32reg = tzc_read_region_base_low(tzc.base, n);
		temp_32reg_h = tzc_read_region_base_high(tzc.base, n);
		DMSG("region_base: 0x%08x%08x", temp_32reg_h, temp_32reg);
		temp_32reg = tzc_read_region_attributes(tzc.base, n);
		DMSG("region sp: %x", temp_32reg >> TZC_ATTR_SP_SHIFT);
		DMSG("region size: %x\n", (temp_32reg & TZC_REGION_SIZE_MASK) >>
				TZC_REGION_SIZE_SHIFT);
	}
	DMSG("exit");
}

#endif /* CFG_TRACE_LEVEL >= TRACE_DEBUG */
