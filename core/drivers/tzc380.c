// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2017-2020 NXP
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

static uint32_t tzc_read_action(vaddr_t base)
{
	return io_read32(base + ACTION_OFF);
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
						      MEM_AREA_IO_SEC,
						      TZC400_REG_SIZE);

	EMSG("Fail address Low 0x%" PRIx32,
	     io_read32(base + FAIL_ADDRESS_LOW_OFF));
	EMSG("Fail address High 0x%" PRIx32,
	     io_read32(base + FAIL_ADDRESS_HIGH_OFF));
	EMSG("Fail Control 0x%" PRIx32, io_read32(base + FAIL_CONTROL_OFF));
	EMSG("Fail Id 0x%" PRIx32, io_read32(base + FAIL_ID));
}

void tzc_int_clear(void)
{
	vaddr_t base = core_mmu_get_va(tzc.base, MEM_AREA_IO_SEC,
				       TZC400_REG_SIZE);

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

uint32_t tzc_get_action(void)
{
	assert(tzc.base);

	return tzc_read_action(tzc.base);
}

int tzc_auto_configure(vaddr_t addr, vaddr_t size, uint32_t attr,
		       uint8_t region)
{
	uint64_t sub_region_size = 0;
	uint64_t area = 0;
	uint8_t lregion = region;
	uint64_t region_size = 0;
	vaddr_t sub_address = 0;
	vaddr_t address = addr;
	uint64_t lsize = size;
	uint32_t mask = 0;
	int i = 0;
	uint8_t pow = 0;

	assert(tzc.base);

	/*
	 * TZC380 RM
	 * For region_attributes_<n> registers, region_size:
	 * Note: The AXI address width, that is AXI_ADDRESS_MSB+1, controls the
	 * upper limit value of the field.
	 */
	pow = tzc.addr_width;

	while (lsize != 0 && pow > 15) {
		region_size = 1ULL << pow;

		/* Case region fits alignment and covers requested area */
		if ((address % region_size == 0) &&
		    ((address + lsize) % region_size == 0)) {
			tzc_configure_region(lregion, address,
					     TZC_ATTR_REGION_SIZE(pow - 1) |
					     TZC_ATTR_REGION_EN_MASK |
					     attr);
			lregion++;
			address += region_size;
			lsize -= region_size;
			pow = tzc.addr_width;
			continue;
		}

		/* Cover area using several subregions */
		sub_region_size = region_size / 8;
		if (address % sub_region_size == 0 &&
		    lsize > 2 * sub_region_size) {
			sub_address = (address / region_size) * region_size;
			mask = 0;
			for (i = 0; i < 8; i++) {
				area = (i + 1) * sub_region_size;
				if (sub_address + area <= address ||
				    sub_address + area > address + lsize) {
					mask |= TZC_ATTR_SUBREGION_DIS(i);
				} else {
					address += sub_region_size;
					lsize -= sub_region_size;
				}
			}
			tzc_configure_region(lregion, sub_address,
					     TZC_ATTR_REGION_SIZE(pow - 1) |
					     TZC_ATTR_REGION_EN_MASK |
					     mask | attr);
			lregion++;
			pow = tzc.addr_width;
			continue;
		}
		pow--;
	}
	assert(lsize == 0);
	assert(address == addr + size);
	return lregion;
}

/*
 * `region_lockdown` is used to lockdown the TZC380 configuration to prevent
 * unintended overwrites of the configuration. Returns TEE_ERROR_SECURITY in
 * case the lockdown fails.
 */
TEE_Result tzc_regions_lockdown(void)
{
	uint32_t val = 0;
	uint32_t check = 0;

	val = LOCKDOWN_RANGE_ENABLE | (tzc.num_regions - 1);
	io_write32(tzc.base + LOCKDOWN_RANGE_OFF, val);
	check = io_read32(tzc.base + LOCKDOWN_RANGE_OFF);
	if (check != val)
		return TEE_ERROR_SECURITY;

	val = LOCKDOWN_SELECT_RANGE_ENABLE;
	io_write32(tzc.base + LOCKDOWN_SELECT_OFF, val);
	check = io_read32(tzc.base + LOCKDOWN_SELECT_OFF);
	if (check != val)
		return TEE_ERROR_SECURITY;

	return TEE_SUCCESS;
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

	DMSG("TZC380 configuration:");
	DMSG("security_inversion_en %x",
	     io_read32(tzc.base + SECURITY_INV_EN_OFF));
	for (n = 0; n <= REGION_MAX; n++) {
		temp_32reg = tzc_read_region_attributes(tzc.base, n);
		if (!(temp_32reg & TZC_ATTR_REGION_EN_MASK))
			continue;

		DMSG("");
		DMSG("region %d", n);
		temp_32reg = tzc_read_region_base_low(tzc.base, n);
		temp_32reg_h = tzc_read_region_base_high(tzc.base, n);
		DMSG("region_base: 0x%08x%08x", temp_32reg_h, temp_32reg);
		temp_32reg = tzc_read_region_attributes(tzc.base, n);
		DMSG("region sp: %x", temp_32reg >> TZC_ATTR_SP_SHIFT);
		DMSG("region size: %x", (temp_32reg & TZC_REGION_SIZE_MASK) >>
				TZC_REGION_SIZE_SHIFT);
	}
	DMSG("Lockdown select: %"PRIx32,
	     io_read32(tzc.base + LOCKDOWN_SELECT_OFF));
	DMSG("Lockdown range: %"PRIx32,
	     io_read32(tzc.base + LOCKDOWN_RANGE_OFF));
	DMSG("Action register: %"PRIx32, tzc_get_action());
	DMSG("exit");
}

#endif /* CFG_TRACE_LEVEL >= TRACE_DEBUG */
