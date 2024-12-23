// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2024, Telechips Inc.
 *
 * Driver for the Orbit Memory Controller.
 * https://www.openedges.com/memorycontroller
 */

#include <assert.h>
#include <drivers/openedges_omc.h>
#include <io.h>
#include <kernel/panic.h>
#include <trace.h>
#include <util.h>

#define ACTION_OFF              U(0x1004)

#define INT_STATUS              U(0x1010)
#define INT_CLEAR               U(0x1014)
#define FAIL_ADDRESS_LOW_OFF    U(0x1020)
#define FAIL_ADDRESS_HIGH_OFF   U(0x1024)
#define FAIL_CONTROL_OFF        U(0x1028)
#define FAIL_ID_OFF             U(0x102c)
#define FAIL_DIRECTION_OFF(d)   (U(0x20) * (d))

#define REGION_COUNT		U(17)
#define REGION_BASE_LOW_OFF     U(0x1100)
#define REGION_BASE_HIGH_OFF    U(0x1104)
#define REGION_TOP_LOW_OFF      U(0x1108)
#define REGION_TOP_HIGH_OFF     U(0x110c)
#define REGION_ATTRIBUTES_OFF   U(0x1110)
#define REGION_ID_ACCESS_OFF    U(0x1114)
#define REGION_NUM_OFF(region)  (U(0x20) * (region))

#define ADDRESS_CTRL0_OFF       U(0x1f00)
#define ADDRESS_CTRL1_OFF       U(0x1f04)
#define REGION0_START_OFF       U(0x1f10)
#define REGION0_END_OFF         U(0x1f14)
#define REGION0_CFG_OFF         U(0x1f18)
#define REGION1_START_OFF       U(0x1f20)
#define REGION1_END_OFF         U(0x1f24)
#define REGION1_CFG_OFF         U(0x1f28)
#define CHIP0_SIZE_OFF          U(0x1f30)
#define CHIP1_SIZE_OFF          U(0x1f34)

#define INT_TYPE_READ           U(0)
#define INT_TYPE_WRITE          U(1)
#define INT_TYPE_MAX            U(2)

#define INT_STATUS_OVERLAP      BIT(16)
#define INT_STATUS_OVERRUN      BIT(8)
#define INT_STATUS_STATUS       BIT(0)
#define INT_STATUS_MASK         (INT_STATUS_OVERLAP | INT_STATUS_OVERRUN | \
				 INT_STATUS_STATUS)

#define INT_CLEAR_CLEAR_SHIFT   U(0)
#define INT_CLEAR_CLEAR_MASK    U(0x1)

#define FAIL_CONTROL_NONSECURE  BIT(21)
#define FAIL_CONTROL_PRIVILEGED BIT(20)

#define FAIL_ID_AID_SHIFT       U(8)
#define FAIL_ID_AID_MASK        GENMASK_32(27, 8)
#define FAIL_ID_MID_SHIFT       U(0)
#define FAIL_ID_MID_MASK        GENMASK_32(7, 0)

#define REG_ATTR_S_WR_EN        BIT(31)
#define REG_ATTR_S_RD_EN        BIT(30)
#define REG_ATTR_FILTER_EN      BIT(0)

struct omc_instance {
	vaddr_t base;
	uint32_t size;
	uint8_t num_filters;
};

static struct omc_instance tzc;

static void omc_write32(uint8_t filter, uint32_t offs, uint32_t val)
{
	vaddr_t filter_offs = filter * tzc.size;

	io_write32(tzc.base + filter_offs + offs, val);
}

static uint32_t omc_read32(uint8_t filter, uint32_t offs)
{
	vaddr_t filter_offs = filter * tzc.size;

	return io_read32(tzc.base + filter_offs + offs);
}

static void omc_write64(uint8_t filter, uint32_t offs, uint64_t val)
{
	vaddr_t filter_offs = filter * tzc.size;

	io_write64(tzc.base + filter_offs + offs, val);
}

static uint64_t omc_read64(uint8_t filter, uint32_t offs)
{
	vaddr_t filter_offs = filter * tzc.size;

	return io_read64(tzc.base + filter_offs + offs);
}

static void omc_write_region_base(uint8_t filter, uint32_t region, uint64_t val)
{
	omc_write64(filter, REGION_BASE_LOW_OFF + REGION_NUM_OFF(region), val);
}

static void omc_write_region_top(uint8_t filter, uint32_t region, uint64_t val)
{
	omc_write64(filter, REGION_TOP_LOW_OFF + REGION_NUM_OFF(region), val);
}

static void omc_write_region_attributes(uint8_t filter, uint32_t region,
					uint32_t val)
{
	omc_write32(filter, REGION_ATTRIBUTES_OFF + REGION_NUM_OFF(region),
		    val);
}

static void omc_write_region_id_access(uint8_t filter, uint32_t region,
				       uint32_t val)
{
	omc_write32(filter, REGION_ID_ACCESS_OFF + REGION_NUM_OFF(region), val);
}

static uint64_t omc_read_start_address(uint8_t filter)
{
	return SHIFT_U64(omc_read32(filter, REGION0_START_OFF), 8);
}

void omc_init(vaddr_t base, uint32_t size, uint8_t num)
{
	assert(base);

	tzc.base = base;
	tzc.size = size;
	tzc.num_filters = num;
}

void omc_configure_region(uint8_t region, const struct omc_region_config *cfg)
{
	uint8_t filter = 0;
	uint32_t attr = 0;
	uint64_t start_addr = 0;

	if (!tzc.base)
		panic("tzc.base is not registered");
	else if (!cfg)
		panic("cfg is null");
	else if (cfg->filters >> tzc.num_filters)
		panic("cfg->filters is overflowed");
	else if (region >= REGION_COUNT)
		panic("region is overflowed");
	else if ((cfg->base | (cfg->top + 1)) & 0xFFF)
		panic("region base or (top + 1) is not 4KB aligned");

	for (filter = 0; filter < tzc.num_filters; filter++) {
		if (cfg->flags & OMC_FLAG_RELATIVE_ADDR)
			start_addr = omc_read_start_address(filter);
		else
			start_addr = 0;

		omc_write_region_base(filter, region, start_addr + cfg->base);
		omc_write_region_top(filter, region, start_addr + cfg->top);

		/* Assign the region to a filter and set secure attributes */
		attr = REG_ATTR_S_WR_EN | REG_ATTR_S_RD_EN;
		if (cfg->filters & BIT(filter))
			attr |= REG_ATTR_FILTER_EN;
		omc_write_region_attributes(filter, region, attr);

		omc_write_region_id_access(filter, region,
					   cfg->ns_device_access);
	}
}

void omc_set_action(enum omc_action action)
{
	uint8_t filter = 0;

	if (!tzc.base)
		panic("tzc.base is null");

	for (filter = 0; filter < tzc.num_filters; filter++)
		omc_write32(filter, ACTION_OFF, (uint32_t)action);
}

void omc_fail_dump(uint8_t filter)
{
	uint64_t __maybe_unused addr = 0;
	uint32_t status = 0;
	uint32_t __maybe_unused ctrl = 0;
	uint32_t __maybe_unused nsaid = 0;
	uint32_t direction = 0;

	for (direction = INT_TYPE_READ; direction < INT_TYPE_MAX; direction++) {
		status = omc_read32(filter,
				    INT_STATUS + FAIL_DIRECTION_OFF(direction));
		if (!(status & INT_STATUS_MASK))
			continue;

		if (status & INT_STATUS_OVERLAP)
			EMSG("Overlap violation on filter %"PRIu8, filter);

		if (status & INT_STATUS_OVERRUN)
			EMSG("Overrun violation on filter %"PRIu8, filter);

		if (status & INT_STATUS_STATUS)
			EMSG("Permission violation on filter %"PRIu8, filter);

		ctrl = omc_read32(filter, FAIL_CONTROL_OFF +
				FAIL_DIRECTION_OFF(direction));
		addr = omc_read64(filter, FAIL_ADDRESS_LOW_OFF +
				FAIL_DIRECTION_OFF(direction));
		nsaid = omc_read32(filter, FAIL_ID_OFF +
				FAIL_DIRECTION_OFF(direction));
		EMSG("Violation @%#"PRIx64
		     ", %ssecure %sprivileged %s, MID %#"PRIx32", AID %#"PRIx32,
		     addr,
		     (ctrl & FAIL_CONTROL_NONSECURE) ? "non-" : "",
		     (ctrl & FAIL_CONTROL_PRIVILEGED) ? "" : "un",
		     (direction == INT_TYPE_WRITE) ? "write" : "read",
		     (nsaid & FAIL_ID_MID_MASK) >> FAIL_ID_MID_SHIFT,
		     (nsaid & FAIL_ID_AID_MASK) >> FAIL_ID_AID_SHIFT);
	}
}

void omc_int_clear(uint8_t filter)
{
	if (!tzc.base)
		panic("tzc.base is null");

	omc_write32(filter, INT_CLEAR, BIT(0));
}
