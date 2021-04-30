/* SPDX-License-Identifier: BSD-2-Clause */
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

#ifndef __DRIVERS_TZC380_H
#define __DRIVERS_TZC380_H

#include <stdint.h>
#include <tee_api_types.h>
#include <trace_levels.h>
#include <types_ext.h>
#include <util.h>

#define TZC400_REG_SIZE		U(0x1000)

#define BUILD_CONFIG_OFF	U(0x000)
#define ACTION_OFF		U(0x004)
#define LOCKDOWN_RANGE_OFF	U(0x008)
#define LOCKDOWN_SELECT_OFF	U(0x00C)
#define INT_STATUS		U(0x010)
#define INT_CLEAR		U(0x014)

#define FAIL_ADDRESS_LOW_OFF	U(0x020)
#define FAIL_ADDRESS_HIGH_OFF	U(0x024)
#define FAIL_CONTROL_OFF	U(0x028)
#define FAIL_ID			U(0x02c)

#define SPECULATION_CTRL_OFF	U(0x030)
#define SECURITY_INV_EN_OFF	U(0x034)

#define REGION_SETUP_LOW_OFF(n)	(U(0x100) + (n) * U(0x10))
#define REGION_SETUP_HIGH_OFF(n) (U(0x104) + (n) * U(0x10))
#define REGION_ATTRIBUTES_OFF(n) (U(0x108) + (n) * U(0x10))

/* ID Registers */
#define PID0_OFF		U(0xfe0)
#define PID1_OFF		U(0xfe4)
#define PID2_OFF		U(0xfe8)
#define PID3_OFF		U(0xfec)
#define PID4_OFF		U(0xfd0)
#define CID0_OFF		U(0xff0)
#define CID1_OFF		U(0xff4)
#define CID2_OFF		U(0xff8)
#define CID3_OFF		U(0xffc)

#define BUILD_CONFIG_AW_SHIFT	U(8)
#define BUILD_CONFIG_AW_MASK	U(0x3f)
#define BUILD_CONFIG_NR_SHIFT	U(0)
#define BUILD_CONFIG_NR_MASK	U(0xf)

#define ACTION_RV_SHIFT		U(0)
#define ACTION_RV_MASK		U(0x3)
#define  ACTION_RV_LOWOK	U(0x0)
#define  ACTION_RV_LOWERR	U(0x1)
#define  ACTION_RV_HIGHOK	U(0x2)
#define  ACTION_RV_HIGHERR	U(0x3)

/* Speculation is enabled by default. */
#define SPECULATION_CTRL_WRITE_DISABLE	BIT(1)
#define SPECULATION_CTRL_READ_DISABLE	BIT(0)

#define INT_STATUS_OVERRUN_SHIFT	U(1)
#define INT_STATUS_OVERRUN_MASK		U(0x1)
#define INT_STATUS_STATUS_SHIFT		U(0)
#define INT_STATUS_STATUS_MASK		U(0x1)

#define INT_CLEAR_CLEAR_SHIFT		U(0)
#define INT_CLEAR_CLEAR_MASK		U(0x1)

#define TZC380_COMPONENT_ID	U(0xb105f00d)
#define TZC380_PERIPH_ID_LOW	U(0x001bb380)
#define TZC380_PERIPH_ID_HIGH	U(0x00000004)

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


#define TZC_SP_NS_W		BIT(0)
#define TZC_SP_NS_R		BIT(1)
#define TZC_SP_S_W		BIT(2)
#define TZC_SP_S_R		BIT(3)

#define TZC_ATTR_SP_SHIFT	U(28)
#define TZC_ATTR_SP_MASK	GENMASK_32(31, 28)
#define TZC_ATTR_SP_ALL		SHIFT_U32(TZC_SP_S_W | TZC_SP_S_R | \
					  TZC_SP_NS_W | TZC_SP_NS_R, \
					  TZC_ATTR_SP_SHIFT)
#define TZC_ATTR_SP_S_RW	SHIFT_U32(TZC_SP_S_W | TZC_SP_S_R, \
					  TZC_ATTR_SP_SHIFT)
#define TZC_ATTR_SP_NS_RW	SHIFT_U32(TZC_SP_NS_W | TZC_SP_NS_R, \
					  TZC_ATTR_SP_SHIFT)

#define TZC_REGION_SIZE_32K	U(0xe)
#define TZC_REGION_SIZE_64K	U(0xf)
#define TZC_REGION_SIZE_128K	U(0x10)
#define TZC_REGION_SIZE_256K	U(0x11)
#define TZC_REGION_SIZE_512K	U(0x12)
#define TZC_REGION_SIZE_1M	U(0x13)
#define TZC_REGION_SIZE_2M	U(0x14)
#define TZC_REGION_SIZE_4M	U(0x15)
#define TZC_REGION_SIZE_8M	U(0x16)
#define TZC_REGION_SIZE_16M	U(0x17)
#define TZC_REGION_SIZE_32M	U(0x18)
#define TZC_REGION_SIZE_64M	U(0x19)
#define TZC_REGION_SIZE_128M	U(0x1a)
#define TZC_REGION_SIZE_256M	U(0x1b)
#define TZC_REGION_SIZE_512M	U(0x1c)
#define TZC_REGION_SIZE_1G	U(0x1d)
#define TZC_REGION_SIZE_2G	U(0x1e)
#define TZC_REGION_SIZE_4G	U(0x1f)
#define TZC_REGION_SIZE_8G	U(0x20)
#define TZC_REGION_SIZE_16G	U(0x21)
#define TZC_REGION_SIZE_32G	U(0x22)
#define TZC_REGION_SIZE_64G	U(0x23)
#define TZC_REGION_SIZE_128G	U(0x24)
#define TZC_REGION_SIZE_256G	U(0x25)
#define TZC_REGION_SIZE_512G	U(0x26)
#define TZC_REGION_SIZE_1T	U(0x27)
#define TZC_REGION_SIZE_2T	U(0x28)
#define TZC_REGION_SIZE_4T	U(0x29)
#define TZC_REGION_SIZE_8T	U(0x2a)
#define TZC_REGION_SIZE_16T	U(0x2b)
#define TZC_REGION_SIZE_32T	U(0x2c)
#define TZC_REGION_SIZE_64T	U(0x2d)
#define TZC_REGION_SIZE_128T	U(0x2e)
#define TZC_REGION_SIZE_256T	U(0x2f)
#define TZC_REGION_SIZE_512T	U(0x30)
#define TZC_REGION_SIZE_1P	U(0x31)
#define TZC_REGION_SIZE_2P	U(0x32)
#define TZC_REGION_SIZE_4P	U(0x33)
#define TZC_REGION_SIZE_8P	U(0x34)
#define TZC_REGION_SIZE_16P	U(0x35)
#define TZC_REGION_SIZE_32P	U(0x36)
#define TZC_REGION_SIZE_64P	U(0x37)
#define TZC_REGION_SIZE_128P	U(0x38)
#define TZC_REGION_SIZE_256P	U(0x39)
#define TZC_REGION_SIZE_512P	U(0x3a)
#define TZC_REGION_SIZE_1E	U(0x3b)
#define TZC_REGION_SIZE_2E	U(0x3c)
#define TZC_REGION_SIZE_4E	U(0x3d)
#define TZC_REGION_SIZE_8E	U(0x3e)
#define TZC_REGION_SIZE_16E	U(0x3f)

#define TZC_REGION_SIZE_SHIFT	U(0x1)
#define TZC_REGION_SIZE_MASK	GENMASK_32(6, 1)
#define TZC_ATTR_REGION_SIZE(s)	SHIFT_U32(s, TZC_REGION_SIZE_SHIFT)

#define TZC_SUBREGION_DIS_SHIFT	U(8)
#define TZC_SUBREGION_DIS_MASK	GENMASK_32(15, 8)
#define TZC_ATTR_SUBREGION_DIS(subreg) \
	(BIT((subreg) + TZC_SUBREGION_DIS_SHIFT) & \
	 TZC_SUBREGION_DIS_MASK)

#define TZC_ATTR_REGION_EN_SHIFT	U(0x0)
#define TZC_ATTR_REGION_EN_MASK		U(0x1)

#define TZC_ATTR_REGION_EN
#define TZC_ATTR_REGION_ENABLE	U(0x1)
#define TZC_ATTR_REGION_DISABLE	U(0x0)

#define LOCKDOWN_RANGE_ENABLE		BIT(31)

#define LOCKDOWN_SELECT_RANGE_ENABLE	BIT(0)

void tzc_init(vaddr_t base);
void tzc_configure_region(uint8_t region, vaddr_t region_base, uint32_t attr);
void tzc_region_enable(uint8_t region);
void tzc_security_inversion_en(vaddr_t base);
void tzc_set_action(enum tzc_action action);
uint32_t tzc_get_action(void);
void tzc_fail_dump(void);
void tzc_int_clear(void);
int tzc_auto_configure(vaddr_t addr, vaddr_t rsize, uint32_t attr,
		       uint8_t region);
TEE_Result tzc_regions_lockdown(void);

#if TRACE_LEVEL >= TRACE_DEBUG
void tzc_dump_state(void);
#else
static inline void tzc_dump_state(void)
{
}
#endif

#endif /* __DRIVERS_TZC400_H */
