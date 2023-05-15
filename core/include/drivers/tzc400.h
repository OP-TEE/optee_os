/* SPDX-License-Identifier: (BSD-2-Clause AND BSD-3-Clause) */
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

#ifndef __DRIVERS_TZC400_H
#define __DRIVERS_TZC400_H

#include <stdint.h>
#include <types_ext.h>
#include <trace_levels.h>
#include <tee_api_types.h>
#include <util.h>

#define TZC400_REG_SIZE		U(0x1000)

#define BUILD_CONFIG_OFF	U(0x000)
#define ACTION_OFF		U(0x004)
#define GATE_KEEPER_OFF		U(0x008)
#define SPECULATION_CTRL_OFF	U(0x00c)
#define INT_STATUS		U(0x010)
#define INT_CLEAR		U(0x014)

#define FAIL_ADDRESS_LOW_OFF	U(0x020)
#define FAIL_ADDRESS_HIGH_OFF	U(0x024)
#define FAIL_CONTROL_OFF	U(0x028)
#define FAIL_ID_OFF		U(0x02c)
#define FAIL_FILTER_OFF(idx)	(U(0x10) * (idx))

#define FAIL_ADDRESS_LOW(idx)	(FAIL_ADDRESS_LOW_OFF + FAIL_FILTER_OFF(idx))
#define FAIL_ADDRESS_HIGH(idx)	(FAIL_ADDRESS_HIGH_OFF + FAIL_FILTER_OFF(idx))
#define FAIL_CONTROL(idx)	(FAIL_CONTROL_OFF + FAIL_FILTER_OFF(idx))
#define FAIL_ID(idx)		(FAIL_ID_OFF + FAIL_FILTER_OFF(idx))

#define REGION_BASE_LOW_OFF	U(0x100)
#define REGION_BASE_HIGH_OFF	U(0x104)
#define REGION_TOP_LOW_OFF	U(0x108)
#define REGION_TOP_HIGH_OFF	U(0x10c)
#define REGION_ATTRIBUTES_OFF	U(0x110)
#define REGION_ID_ACCESS_OFF	U(0x114)
#define REGION_NUM_OFF(region)  (U(0x20) * (region))

/* ID Registers */
#define PID0_OFF		U(0xfe0)
#define PID1_OFF		U(0xfe4)
#define PID2_OFF		U(0xfe8)
#define PID3_OFF		U(0xfec)
#define PID4_OFF		U(0xfd0)
#define PID5_OFF		U(0xfd4)
#define PID6_OFF		U(0xfd8)
#define PID7_OFF		U(0xfdc)
#define CID0_OFF		U(0xff0)
#define CID1_OFF		U(0xff4)
#define CID2_OFF		U(0xff8)
#define CID3_OFF		U(0xffc)

#define BUILD_CONFIG_NF_SHIFT	U(24)
#define BUILD_CONFIG_NF_MASK	U(0x3)
#define BUILD_CONFIG_AW_SHIFT	U(8)
#define BUILD_CONFIG_AW_MASK	U(0x3f)
#define BUILD_CONFIG_NR_SHIFT	U(0)
#define BUILD_CONFIG_NR_MASK	U(0x1f)

/* Not describing the case where regions 1 to 8 overlap */
#define ACTION_RV_SHIFT		U(0)
#define ACTION_RV_MASK		U(0x3)
#define  ACTION_RV_LOWOK	U(0x0)
#define  ACTION_RV_LOWERR	U(0x1)
#define  ACTION_RV_HIGHOK	U(0x2)
#define  ACTION_RV_HIGHERR	U(0x3)

/*
 * Number of gate keepers is implementation defined. But we know the max for
 * this device is 4. Get implementation details from BUILD_CONFIG.
 */
#define GATE_KEEPER_OS_SHIFT	U(16)
#define GATE_KEEPER_OS_MASK	U(0xf)
#define GATE_KEEPER_OR_SHIFT	U(0)
#define GATE_KEEPER_OR_MASK	U(0xf)
#define GATE_KEEPER_FILTER_MASK	U(0x1)

/* Speculation is enabled by default. */
#define SPECULATION_CTRL_WRITE_DISABLE	BIT(1)
#define SPECULATION_CTRL_READ_DISABLE	BIT(0)

/* Max number of filters allowed is 4. */
#define INT_STATUS_OVERLAP_SHIFT	U(16)
#define INT_STATUS_OVERLAP_MASK		U(0xf)
#define INT_STATUS_OVERRUN_SHIFT	U(8)
#define INT_STATUS_OVERRUN_MASK		U(0xf)
#define INT_STATUS_STATUS_SHIFT		U(0)
#define INT_STATUS_STATUS_MASK		U(0xf)

#define INT_CLEAR_CLEAR_SHIFT		U(0)
#define INT_CLEAR_CLEAR_MASK		U(0xf)

/* If set write access, else read access */
#define FAIL_CONTROL_DIRECTION_WRITE	BIT(24)
/* If set non-secure access, else secure access */
#define FAIL_CONTROL_NONSECURE		BIT(21)
/* If set privileged access, else unprivileged access */
#define FAIL_CONTROL_PRIVILEGED		BIT(20)

/*
 * FAIL_ID_ID_MASK depends on AID_WIDTH which is platform specific.
 * Platform should provide the value on initialisation.
 */
#define FAIL_ID_VNET_SHIFT		U(24)
#define FAIL_ID_VNET_MASK		U(0xf)
#define FAIL_ID_ID_SHIFT		U(0)

/* Used along with 'enum tzc_region_attributes' below */
#define REG_ATTR_SEC_SHIFT		U(30)
#define REG_ATTR_F_EN_SHIFT		U(0)
#define REG_ATTR_F_EN_MASK		U(0xf)
#define REG_ATTR_FILTER_BIT(x)		SHIFT_U32(BIT(x), REG_ATTR_F_EN_SHIFT)
#define REG_ATTR_FILTER_BIT_ALL		SHIFT_U32(REG_ATTR_F_EN_MASK, \
						  REG_ATTR_F_EN_SHIFT)

#define REGION_ID_ACCESS_NSAID_WR_EN_SHIFT	U(16)
#define REGION_ID_ACCESS_NSAID_RD_EN_SHIFT	U(0)
#define REGION_ID_ACCESS_NSAID_ID_MASK		U(0xf)


/* Macros for setting Region ID access permissions based on NSAID */
#define TZC_REGION_ACCESS_RD(id)					\
		SHIFT_U32(BIT(id & REGION_ID_ACCESS_NSAID_ID_MASK), \
			  REGION_ID_ACCESS_NSAID_RD_EN_SHIFT)
#define TZC_REGION_ACCESS_WR(id)					\
		SHIFT_U32(BIT(id & REGION_ID_ACCESS_NSAID_ID_MASK), \
			  REGION_ID_ACCESS_NSAID_WR_EN_SHIFT)
#define TZC_REGION_ACCESS_RDWR(id)					\
		(TZC_REGION_ACCESS_RD(id) | TZC_REGION_ACCESS_WR(id))

/* Filters are bit mapped 0 to 3. */
#define TZC400_COMPONENT_ID	U(0xb105f00d)

/*******************************************************************************
 * Function & variable prototypes
 ******************************************************************************/

/*
 * What type of action is expected when an access violation occurs.
 * The memory requested is zeroed. But we can also raise and event to
 * let the system know it happened.
 * We can raise an interrupt(INT) and/or cause an exception(ERR).
 *  TZC_ACTION_NONE    - No interrupt, no Exception
 *  TZC_ACTION_ERR     - No interrupt, raise exception -> sync external
 *                       data abort
 *  TZC_ACTION_INT     - Raise interrupt, no exception
 *  TZC_ACTION_ERR_INT - Raise interrupt, raise exception -> sync
 *                       external data abort
 */
enum tzc_action {
	TZC_ACTION_NONE = 0,
	TZC_ACTION_ERR = 1,
	TZC_ACTION_INT = 2,
	TZC_ACTION_ERR_INT = (TZC_ACTION_ERR | TZC_ACTION_INT)
};

/*
 * Controls secure access to a region. If not enabled secure access is not
 * allowed to region.
 */
enum tzc_region_attributes {
	TZC_REGION_S_NONE = 0,
	TZC_REGION_S_RD = 1,
	TZC_REGION_S_WR = 2,
	TZC_REGION_S_RDWR = (TZC_REGION_S_RD | TZC_REGION_S_WR)
};

struct tzc_region_config {
	uint32_t filters;
	vaddr_t base;
	vaddr_t top;
	enum tzc_region_attributes sec_attr;
	uint32_t ns_device_access;
};

void tzc_init(vaddr_t base);
void tzc_configure_region(uint8_t region, const struct tzc_region_config *cfg);
TEE_Result tzc_get_region_config(uint8_t region, struct tzc_region_config *cfg);
void tzc_enable_filters(void);
void tzc_disable_filters(void);
void tzc_set_action(enum tzc_action action);

void tzc_fail_dump(void);
void tzc_int_clear(void);

#if TRACE_LEVEL >= TRACE_DEBUG
void tzc_dump_state(void);
#else
static inline void tzc_dump_state(void)
{
}
#endif

#endif /* __DRIVERS_TZC400_H */
