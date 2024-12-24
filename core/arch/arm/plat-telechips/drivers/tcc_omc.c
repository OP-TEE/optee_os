// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2024, Telechips Inc.
 */

#include <io.h>
#include <kernel/panic.h>
#include <drivers/tcc_omc.h>
#include <util.h>
#include <trace.h>

/*
 * Implementation defined values used to validate inputs later.
 * Filters : max of 4 ; 0 to 3
 * Regions : max of 17 ; 0 to 16
 * Address width : Values between 32 to 64
 */
struct omc_instance {
	vaddr_t base;
	uint32_t size;
	uint8_t num_filters;
	uint8_t num_regions;
};

static struct omc_instance tzc;

static inline void omc_write32(uint8_t filter, uint32_t offs, uint32_t val)
{
	vaddr_t filter_offs = (vaddr_t)filter * tzc.size;

	io_write32(tzc.base + filter_offs + offs, val);
}

static inline uint32_t omc_read32(uint8_t filter, uint32_t offs)
{
	vaddr_t filter_offs = (vaddr_t)filter * tzc.size;

	return io_read32(tzc.base + filter_offs + offs);
}

static inline void omc_write64(uint8_t filter, uint32_t offs, uint64_t val)
{
	vaddr_t filter_offs = (vaddr_t)filter * tzc.size;

	io_write64(tzc.base + filter_offs + offs, val);
}

static inline uint64_t omc_read64(uint8_t filter, uint32_t offs)
{
	vaddr_t filter_offs = (vaddr_t)filter * tzc.size;

	return io_read64(tzc.base + filter_offs + offs);
}

static inline uint64_t omc_read_region_base(uint8_t filter, uint32_t region)
{
	return omc_read64(filter, REGION_BASE_LOW_OFF + REGION_NUM_OFF(region));
}

static inline void omc_write_region_base(uint8_t filter, uint32_t region,
					 uint64_t val)
{
	if ((val >> 32) == U(0)) {
		val |= (((uint64_t)omc_read32(filter,
					      REGION0_START_OFF)) << 8);
	}
	omc_write64(filter, REGION_BASE_LOW_OFF + REGION_NUM_OFF(region), val);
}

static inline uint64_t omc_read_region_top(uint8_t filter, uint32_t region)
{
	return omc_read64(filter, REGION_TOP_LOW_OFF + REGION_NUM_OFF(region));
}

static inline void omc_write_region_top(uint8_t filter, uint32_t region,
					uint64_t val)
{
	if ((val >> 32) == U(0)) {
		val |= (((uint64_t)omc_read32(filter,
					      REGION0_START_OFF)) << 8);
	}
	omc_write64(filter, REGION_TOP_LOW_OFF + REGION_NUM_OFF(region), val);
}

static uint32_t omc_read_region_attributes(uint8_t filter, uint32_t region)
{
	return omc_read32(filter, REGION_ATTRIBUTES_OFF +
			REGION_NUM_OFF(region));
}

static void omc_write_region_attributes(uint8_t filter, uint32_t region,
					uint32_t val)
{
	omc_write32(filter, REGION_ATTRIBUTES_OFF + REGION_NUM_OFF(region),
		    val);
}

static uint32_t omc_read_region_id_access(uint8_t filter, uint32_t region)
{
	return omc_read32(filter,
			  REGION_ID_ACCESS_OFF + REGION_NUM_OFF(region));
}

static void omc_write_region_id_access(uint8_t filter, uint32_t region,
				       uint32_t val)
{
	omc_write32(filter, REGION_ID_ACCESS_OFF + REGION_NUM_OFF(region), val);
}

void omc_init(vaddr_t base, uint32_t size, uint8_t num)
{
	if (base == U(0))
		panic("base address is null");

	tzc.base = base;
	tzc.size = size;
	tzc.num_filters = num;
	tzc.num_regions = U(17);
}

void omc_configure_region(uint8_t region, const struct tzc_region_config *cfg)
{
	uint8_t filter;

	if (tzc.base == U(0))
		panic("tzc.base is not registered");
	else if (!cfg)
		panic("cfg is null");
	else if ((cfg->filters >> tzc.num_filters) != U(0))
		panic("cfg->filters is overflowed");
	else if (region >= tzc.num_regions)
		panic("region is overflowed");
	else if (((cfg->base | (cfg->top + U(1))) & U(4095)) != U(0))
		panic("region base or (top + 1) is not 4KB aligned");
	else if (cfg->sec_attr > TZC_REGION_S_RDWR)
		panic("invalied cfg->sec_attr");

	for (filter = 0; filter < tzc.num_filters; filter++) {
		omc_write_region_base(filter, region, cfg->base);
		omc_write_region_top(filter, region, cfg->top);

		/* Assign the region to a filter and set secure attributes */
		omc_write_region_attributes(filter, region,
					    ((uint32_t)cfg->sec_attr <<
					     REG_ATTR_SEC_SHIFT) |
					    (((cfg->filters &
					       (UL(1) << filter)) != U(0)) ?
					     U(0x1) : U(0x0)));

		omc_write_region_id_access(filter, region,
					   cfg->ns_device_access);
	}
}

TEE_Result omc_get_region_config(uint8_t region, struct tzc_region_config *cfg)
{
	uint32_t val32 = 0;
	uint8_t filter;
	TEE_Result res;

	if (region >= tzc.num_regions) {
		res = TEE_ERROR_GENERIC;
	} else {
		cfg->base = (vaddr_t)omc_read_region_base(0, region);
		cfg->top = (vaddr_t)omc_read_region_top(0, region);

		cfg->ns_device_access = omc_read_region_id_access(0, region);

		val32 = omc_read_region_attributes(0, region);
		val32 = val32 >> REG_ATTR_SEC_SHIFT;
		cfg->sec_attr = (enum tzc_region_attributes)(val32 & U(0x3));

		cfg->filters = 0;
		for (filter = 0; filter < tzc.num_filters; filter++) {
			val32 = omc_read_region_attributes(filter, region);
			if ((val32 & REG_ATTR_F_EN_MASK) != U(0))
				cfg->filters |= (((uint32_t)1) << filter);
		}

		res = TEE_SUCCESS;
	}

	return res;
}

void omc_set_action(enum tzc_action action)
{
	uint8_t filter;

	if (tzc.base == U(0))
		panic("tzc.base is null");

	/*
	 * - Currently no handler is provided to trap an error via interrupt
	 *   or exception.
	 * - The interrupt action has not been tested.
	 */
	for (filter = 0; filter < tzc.num_filters; filter++)
		omc_write32(filter, ACTION_OFF, (uint32_t)action);
}

void omc_fail_dump(uint8_t filter)
{
	uint64_t __maybe_unused addr = 0;
	uint32_t status, __maybe_unused ctrl, __maybe_unused nsaid;
	uint32_t direction;

	for (direction = OMC_INT_READ; direction < OMC_INT_MAX; direction++) {
		status = omc_read32(filter,
				    INT_STATUS + FAIL_DIRECTION_OFF(direction));
		if (((status & INT_STATUS_OVERLAP) == U(0)) &&
		    ((status & INT_STATUS_OVERRUN) == U(0)) &&
		    ((status & INT_STATUS_STATUS) == U(0))) {
			continue;
		}

		if ((status & INT_STATUS_OVERLAP) != U(0))
			EMSG("Overlap violation on filter %u", filter);

		if ((status & INT_STATUS_OVERRUN) != U(0))
			EMSG("Overrun violation on filter %u", filter);

		if ((status & INT_STATUS_STATUS) != U(0))
			EMSG("Permission violation on filter %u", filter);

		ctrl = omc_read32(filter, FAIL_CONTROL_OFF +
				FAIL_DIRECTION_OFF(direction));
		addr = omc_read64(filter, FAIL_ADDRESS_LOW_OFF +
				FAIL_DIRECTION_OFF(direction));
		nsaid = omc_read32(filter, FAIL_ID_OFF +
				FAIL_DIRECTION_OFF(direction));
		EMSG("Violation @0x%"PRIx64
		     ", %ssecure %sprivileged %s, MID %02x, AID %"PRIx32,
		     addr,
		     ((ctrl & FAIL_CONTROL_NONSECURE) != U(0)) ? "non-" : "",
		     ((ctrl & FAIL_CONTROL_PRIVILEGED) != U(0)) ? "" : "un",
		     (direction == OMC_INT_WRITE) ? "write" : "read",
		     (nsaid >> FAIL_ID_MID_SHIFT) & FAIL_ID_MID_MASK,
		     (nsaid >> FAIL_ID_AID_SHIFT) & FAIL_ID_AID_MASK);
	}
}

void omc_int_clear(uint8_t filter)
{
	if (tzc.base == U(0))
		panic("tzc.base is null");

	omc_write32(filter, INT_CLEAR, BIT(0));
}
