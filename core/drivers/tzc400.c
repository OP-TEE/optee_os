// SPDX-License-Identifier: (BSD-2-Clause AND BSD-3-Clause)
/*
 * Copyright (c) 2015, Linaro Limited
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
 /*
 * Copyright (c) 2014, ARM Limited and Contributors. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * Neither the name of ARM nor the names of its contributors may be used
 * to endorse or promote products derived from this software without specific
 * prior written permission.
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
#include <drivers/tzc400.h>
#include <io.h>
#include <kernel/panic.h>
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
	uint8_t num_filters;
	uint8_t num_regions;
};

static struct tzc_instance tzc;


static uint32_t tzc_read_build_config(vaddr_t base)
{
	return io_read32(base + BUILD_CONFIG_OFF);
}

static uint32_t tzc_read_gate_keeper(vaddr_t base)
{
	return io_read32(base + GATE_KEEPER_OFF);
}

static void tzc_write_gate_keeper(vaddr_t base, uint32_t val)
{
	io_write32(base + GATE_KEEPER_OFF, val);
}

static void tzc_write_action(vaddr_t base, enum tzc_action action)
{
	io_write32(base + ACTION_OFF, action);
}

static uint32_t tzc_read_region_base_low(vaddr_t base, uint32_t region)
{
	return io_read32(base + REGION_BASE_LOW_OFF + REGION_NUM_OFF(region));
}

static void tzc_write_region_base_low(vaddr_t base, uint32_t region,
				      uint32_t val)
{
	io_write32(base + REGION_BASE_LOW_OFF + REGION_NUM_OFF(region), val);
}

static uint32_t tzc_read_region_base_high(vaddr_t base, uint32_t region)
{
	return io_read32(base + REGION_BASE_HIGH_OFF + REGION_NUM_OFF(region));
}

static void tzc_write_region_base_high(vaddr_t base, uint32_t region,
				       uint32_t val)
{
	io_write32(base + REGION_BASE_HIGH_OFF + REGION_NUM_OFF(region), val);
}

static uint32_t tzc_read_region_top_low(vaddr_t base, uint32_t region)
{
	return io_read32(base + REGION_TOP_LOW_OFF + REGION_NUM_OFF(region));
}

static void tzc_write_region_top_low(vaddr_t base, uint32_t region,
				     uint32_t val)
{
	io_write32(base + REGION_TOP_LOW_OFF + REGION_NUM_OFF(region), val);
}

static uint32_t tzc_read_region_top_high(vaddr_t base, uint32_t region)
{
	return io_read32(base + REGION_TOP_HIGH_OFF + REGION_NUM_OFF(region));
}

static void tzc_write_region_top_high(vaddr_t base, uint32_t region,
				      uint32_t val)
{
	io_write32(base + REGION_TOP_HIGH_OFF +	REGION_NUM_OFF(region), val);
}

static uint32_t tzc_read_region_attributes(vaddr_t base, uint32_t region)
{
	return io_read32(base + REGION_ATTRIBUTES_OFF + REGION_NUM_OFF(region));
}

static void tzc_write_region_attributes(vaddr_t base, uint32_t region,
					uint32_t val)
{
	io_write32(base + REGION_ATTRIBUTES_OFF + REGION_NUM_OFF(region), val);
}

static uint32_t tzc_read_region_id_access(vaddr_t base, uint32_t region)
{
	return io_read32(base + REGION_ID_ACCESS_OFF + REGION_NUM_OFF(region));
}

static void tzc_write_region_id_access(vaddr_t base, uint32_t region,
				       uint32_t val)
{
	io_write32(base + REGION_ID_ACCESS_OFF + REGION_NUM_OFF(region), val);
}

static uint32_t tzc_read_component_id(vaddr_t base)
{
	uint32_t id;

	id = io_read8(base + CID0_OFF);
	id |= SHIFT_U32(io_read8(base + CID1_OFF), 8);
	id |= SHIFT_U32(io_read8(base + CID2_OFF), 16);
	id |= SHIFT_U32(io_read8(base + CID3_OFF), 24);

	return id;
}

static uint32_t tzc_get_gate_keeper(vaddr_t base, uint8_t filter)
{
	uint32_t tmp;

	tmp = (tzc_read_gate_keeper(base) >> GATE_KEEPER_OS_SHIFT) &
		GATE_KEEPER_OS_MASK;

	return (tmp >> filter) & GATE_KEEPER_FILTER_MASK;
}

/* This function is not MP safe. */
static void tzc_set_gate_keeper(vaddr_t base, uint8_t filter, uint32_t val)
{
	uint32_t tmp;

	/* Upper half is current state. Lower half is requested state. */
	tmp = (tzc_read_gate_keeper(base) >> GATE_KEEPER_OS_SHIFT) &
		GATE_KEEPER_OS_MASK;

	if (val)
		tmp |=  (1 << filter);
	else
		tmp &= ~(1 << filter);

	tzc_write_gate_keeper(base, (tmp & GATE_KEEPER_OR_MASK) <<
			      GATE_KEEPER_OR_SHIFT);

	/* Wait here until we see the change reflected in the TZC status. */
	while (((tzc_read_gate_keeper(base) >> GATE_KEEPER_OS_SHIFT) &
		GATE_KEEPER_OS_MASK) != tmp)
		;
}


void tzc_init(vaddr_t base)
{
	uint32_t tzc_id, tzc_build;

	assert(base);
	tzc.base = base;

	/*
	 * We expect to see a tzc400. Check component ID. The TZC-400 TRM shows
	 * component ID is expected to be "0xB105F00D".
	 */
	tzc_id = tzc_read_component_id(tzc.base);
	if (tzc_id != TZC400_COMPONENT_ID) {
		EMSG("TZC : Wrong device ID (0x%" PRIx32 ")", tzc_id);
		panic();
	}

	/* Save values we will use later. */
	tzc_build = tzc_read_build_config(tzc.base);
	tzc.num_filters = ((tzc_build >> BUILD_CONFIG_NF_SHIFT) &
			   BUILD_CONFIG_NF_MASK) + 1;
	tzc.addr_width  = ((tzc_build >> BUILD_CONFIG_AW_SHIFT) &
			   BUILD_CONFIG_AW_MASK) + 1;
	tzc.num_regions = ((tzc_build >> BUILD_CONFIG_NR_SHIFT) &
			   BUILD_CONFIG_NR_MASK) + 1;
}

static uint32_t addr_low(vaddr_t addr)
{
	return (uint32_t)addr;
}

static uint32_t addr_high(vaddr_t addr __unused)
{
#if (UINTPTR_MAX == UINT64_MAX)
	return (addr >> 32);
#else
	return 0;
#endif
}


/*
 * `tzc_configure_region` is used to program regions into the TrustZone
 * controller. A region can be associated with more than one filter. The
 * associated filters are passed in as a bitmap (bit0 = filter0).
 * NOTE:
 * The region 0 covers the whole address space and is enabled on all filters,
 * this cannot be changed. It is, however, possible to change some region 0
 * permissions.
 */
void tzc_configure_region(uint8_t region, const struct tzc_region_config *cfg)
{
	assert(tzc.base && cfg);

	/* Do range checks on filters and regions. */
	assert(((cfg->filters >> tzc.num_filters) == 0) &&
	       (region < tzc.num_regions));

	/*
	 * Do address range check based on TZC configuration. A 64bit address is
	 * the max and expected case.
	 */
#if (UINTPTR_MAX == UINT64_MAX)
	assert(((cfg->top <= (UINT64_MAX >> (64 - tzc.addr_width))) &&
		(cfg->base < cfg->top)));
#endif
	/* region_base and (region_top + 1) must be 4KB aligned */
	assert(((cfg->base | (cfg->top + 1)) & (4096 - 1)) == 0);

	assert(cfg->sec_attr <= TZC_REGION_S_RDWR);

	/*
	 * Inputs look ok, start programming registers.
	 * All the address registers are 32 bits wide and have a LOW and HIGH
	 * component used to construct a up to a 64bit address.
	 */
	tzc_write_region_base_low(tzc.base, region, addr_low(cfg->base));
	tzc_write_region_base_high(tzc.base, region, addr_high(cfg->base));

	tzc_write_region_top_low(tzc.base, region, addr_low(cfg->top));
	tzc_write_region_top_high(tzc.base, region, addr_high(cfg->top));

	/* Assign the region to a filter and set secure attributes */
	tzc_write_region_attributes(tzc.base, region,
				    (cfg->sec_attr << REG_ATTR_SEC_SHIFT) |
				    cfg->filters);

	/*
	 * Specify which non-secure devices have permission to access this
	 * region.
	 */
	tzc_write_region_id_access(tzc.base, region, cfg->ns_device_access);
}

TEE_Result tzc_get_region_config(uint8_t region, struct tzc_region_config *cfg)
{
	uint32_t val32 = 0;

	if (region >= tzc.num_regions)
		return TEE_ERROR_GENERIC;

	cfg->base = reg_pair_to_64(tzc_read_region_base_high(tzc.base, region),
				   tzc_read_region_base_low(tzc.base, region));
	cfg->top = reg_pair_to_64(tzc_read_region_top_high(tzc.base, region),
				  tzc_read_region_top_low(tzc.base, region));

	cfg->ns_device_access = tzc_read_region_id_access(tzc.base, region);

	val32 = tzc_read_region_attributes(tzc.base, region);
	cfg->sec_attr = val32 >> REG_ATTR_SEC_SHIFT;
	cfg->filters = val32 & REG_ATTR_F_EN_MASK;

	return TEE_SUCCESS;
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


void tzc_enable_filters(void)
{
	uint32_t state;
	uint32_t filter;

	assert(tzc.base);

	for (filter = 0; filter < tzc.num_filters; filter++) {
		state = tzc_get_gate_keeper(tzc.base, filter);
		if (state) {
			/*
			 * The TZC filter is already configured. Changing the
			 * programmer's view in an active system can cause
			 * unpredictable behavior therefore panic for now rather
			 * than try to determine whether this is safe in this
			 * instance. See:
			 * http://infocenter.arm.com/help/index.jsp?\
			 * topic=/com.arm.doc.ddi0504c/CJHHECBF.html
			 */
			EMSG("TZC : Filter %d Gatekeeper already enabled",
			     filter);
			panic();
		}
		tzc_set_gate_keeper(tzc.base, filter, 1);
	}
}


void tzc_disable_filters(void)
{
	uint32_t filter;

	assert(tzc.base);

	/*
	 * We don't do the same state check as above as the Gatekeepers are
	 * disabled after reset.
	 */
	for (filter = 0; filter < tzc.num_filters; filter++)
		tzc_set_gate_keeper(tzc.base, filter, 0);
}

static bool __maybe_unused write_not_read(unsigned int filter)
{
	return io_read32(tzc.base + FAIL_CONTROL(filter)) &
	       FAIL_CONTROL_DIRECTION_WRITE;
}

static bool __maybe_unused nonsecure_not_secure(unsigned int filter)
{
	return io_read32(tzc.base + FAIL_CONTROL(filter)) &
	       FAIL_CONTROL_NONSECURE;
}

static bool __maybe_unused priv_not_unpriv(unsigned int filter)
{
	return io_read32(tzc.base + FAIL_CONTROL(filter)) &
	       FAIL_CONTROL_PRIVILEGED;
}

static void dump_fail_filter(unsigned int filter)
{
	uint64_t __maybe_unused addr = 0;
	uint32_t status = io_read32(tzc.base + INT_STATUS);

	if (!(status & BIT(filter + INT_STATUS_OVERLAP_SHIFT)) &&
	    !(status & BIT(filter + INT_STATUS_OVERRUN_SHIFT)) &&
	    !(status & BIT(filter + INT_STATUS_STATUS_SHIFT)))
		return;

	if (status & BIT(filter + INT_STATUS_OVERLAP_SHIFT))
		EMSG("Overlap violation on filter %u", filter);

	if (status & BIT(filter + INT_STATUS_OVERRUN_SHIFT))
		EMSG("Overrun violation on filter %u", filter);

	if (status & BIT(filter + INT_STATUS_STATUS_SHIFT))
		EMSG("Permission violation on filter %u", filter);

	addr = reg_pair_to_64(io_read32(tzc.base + FAIL_ADDRESS_HIGH(filter)),
			      io_read32(tzc.base + FAIL_ADDRESS_LOW(filter)));

	EMSG("Violation @0x%"PRIx64", %ssecure %sprivileged %s, AXI ID %"PRIx32,
	     addr,
	     nonsecure_not_secure(filter) ? "non-" : "",
	     priv_not_unpriv(filter) ? "" : "un",
	     write_not_read(filter) ? "write" : "read",
	     io_read32(tzc.base + FAIL_ID(filter)));
}

/*
 * Dump info when TZC400 catches an unallowed access with TZC
 * interrupt enabled.
 */
void tzc_fail_dump(void)
{
	unsigned int filter = 0;

	for (filter = 0; filter < tzc.num_filters; filter++)
		dump_fail_filter(filter);
}

void tzc_int_clear(void)
{
	assert(tzc.base);

	io_setbits32(tzc.base + INT_CLEAR, GENMASK_32(tzc.num_filters - 1, 0));
}

#if TRACE_LEVEL >= TRACE_DEBUG

#define	REGION_MAX		8
static const __maybe_unused char * const tzc_attr_msg[] = {
	"TZC_REGION_S_NONE",
	"TZC_REGION_S_RD",
	"TZC_REGION_S_WR",
	"TZC_REGION_S_RDWR"
};

void tzc_dump_state(void)
{
	uint32_t n;
	uint32_t temp_32reg, temp_32reg_h;
	unsigned int filter = 0;

	for (n = 0; n <= REGION_MAX; n++) {
		temp_32reg = tzc_read_region_attributes(tzc.base, n);
		if (!(temp_32reg & REG_ATTR_F_EN_MASK))
			continue;

		DMSG("region %d", n);
		temp_32reg = tzc_read_region_base_low(tzc.base, n);
		temp_32reg_h = tzc_read_region_base_high(tzc.base, n);
		DMSG("region_base: 0x%08x%08x", temp_32reg_h, temp_32reg);
		temp_32reg = tzc_read_region_top_low(tzc.base, n);
		temp_32reg_h = tzc_read_region_top_high(tzc.base, n);
		DMSG("region_top: 0x%08x%08x", temp_32reg_h, temp_32reg);
		temp_32reg = tzc_read_region_attributes(tzc.base, n);
		DMSG("secure rw: %s",
		     tzc_attr_msg[temp_32reg >> REG_ATTR_SEC_SHIFT]);

		for (filter = 0; filter < tzc.num_filters; filter++)
			if (temp_32reg & BIT(filter))
				DMSG("filter %u enable", filter);
	}
}

#endif /* CFG_TRACE_LEVEL >= TRACE_DEBUG */
