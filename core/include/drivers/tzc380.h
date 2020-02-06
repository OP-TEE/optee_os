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

#define TZC400_REG_SIZE		0x1000

#define BUILD_CONFIG_OFF	0x000
#define ACTION_OFF		0x004
#define LOCKDOWN_RANGE_OFF	0x008
#define LOCKDOWN_SELECT_OFF	0x00C
#define INT_STATUS		0x010
#define INT_CLEAR		0x014

#define FAIL_ADDRESS_LOW_OFF	0x020
#define FAIL_ADDRESS_HIGH_OFF	0x024
#define FAIL_CONTROL_OFF	0x028
#define FAIL_ID			0x02c

#define SPECULATION_CTRL_OFF	0x030
#define SECURITY_INV_EN_OFF	0x034

#define REGION_SETUP_LOW_OFF(n)	(0x100 + n * 0x10)
#define REGION_SETUP_HIGH_OFF(n) (0x104 + n * 0x10)
#define REGION_ATTRIBUTES_OFF(n) (0x108 + n * 0x10)

/* ID Registers */
#define PID0_OFF		0xfe0
#define PID1_OFF		0xfe4
#define PID2_OFF		0xfe8
#define PID3_OFF		0xfec
#define PID4_OFF		0xfd0
#define CID0_OFF		0xff0
#define CID1_OFF		0xff4
#define CID2_OFF		0xff8
#define CID3_OFF		0xffc

#define BUILD_CONFIG_AW_SHIFT	8
#define BUILD_CONFIG_AW_MASK	0x3f
#define BUILD_CONFIG_NR_SHIFT	0
#define BUILD_CONFIG_NR_MASK	0xf

#define ACTION_RV_SHIFT		0
#define ACTION_RV_MASK		0x3
#define  ACTION_RV_LOWOK	0x0
#define  ACTION_RV_LOWERR	0x1
#define  ACTION_RV_HIGHOK	0x2
#define  ACTION_RV_HIGHERR	0x3

/* Speculation is enabled by default. */
#define SPECULATION_CTRL_WRITE_DISABLE	BIT(1)
#define SPECULATION_CTRL_READ_DISABLE	BIT(0)

#define INT_STATUS_OVERRUN_SHIFT	1
#define INT_STATUS_OVERRUN_MASK		0x1
#define INT_STATUS_STATUS_SHIFT		0
#define INT_STATUS_STATUS_MASK		0x1

#define INT_CLEAR_CLEAR_SHIFT		0
#define INT_CLEAR_CLEAR_MASK		0x1

#define TZC380_COMPONENT_ID	0xb105f00d
#define TZC380_PERIPH_ID_LOW	0x001bb380
#define TZC380_PERIPH_ID_HIGH	0x00000004

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

#define TZC_ATTR_SP_SHIFT	28
#define TZC_ATTR_SP_MASK	GENMASK_32(31, 28)
#define TZC_ATTR_SP_ALL		((TZC_SP_S_W | TZC_SP_S_R | TZC_SP_NS_W | \
				TZC_SP_NS_R) << TZC_ATTR_SP_SHIFT)
#define TZC_ATTR_SP_S_RW	((TZC_SP_S_W | TZC_SP_S_R) << \
				 TZC_ATTR_SP_SHIFT)
#define TZC_ATTR_SP_NS_RW	((TZC_SP_NS_W | TZC_SP_NS_R) << \
				TZC_ATTR_SP_SHIFT)

#define TZC_REGION_SIZE_32K	0xe
#define TZC_REGION_SIZE_64K	0xf
#define TZC_REGION_SIZE_128K	0x10
#define TZC_REGION_SIZE_256K	0x11
#define TZC_REGION_SIZE_512K	0x12
#define TZC_REGION_SIZE_1M	0x13
#define TZC_REGION_SIZE_2M	0x14
#define TZC_REGION_SIZE_4M	0x15
#define TZC_REGION_SIZE_8M	0x16
#define TZC_REGION_SIZE_16M	0x17
#define TZC_REGION_SIZE_32M	0x18
#define TZC_REGION_SIZE_64M	0x19
#define TZC_REGION_SIZE_128M	0x1a
#define TZC_REGION_SIZE_256M	0x1b
#define TZC_REGION_SIZE_512M	0x1c
#define TZC_REGION_SIZE_1G	0x1d
#define TZC_REGION_SIZE_2G	0x1e
#define TZC_REGION_SIZE_4G	0x1f
#define TZC_REGION_SIZE_8G	0x20
#define TZC_REGION_SIZE_16G	0x21
#define TZC_REGION_SIZE_32G	0x22
#define TZC_REGION_SIZE_64G	0x23
#define TZC_REGION_SIZE_128G	0x24
#define TZC_REGION_SIZE_256G	0x25
#define TZC_REGION_SIZE_512G	0x26
#define TZC_REGION_SIZE_1T	0x27
#define TZC_REGION_SIZE_2T	0x28
#define TZC_REGION_SIZE_4T	0x29
#define TZC_REGION_SIZE_8T	0x2a
#define TZC_REGION_SIZE_16T	0x2b
#define TZC_REGION_SIZE_32T	0x2c
#define TZC_REGION_SIZE_64T	0x2d
#define TZC_REGION_SIZE_128T	0x2e
#define TZC_REGION_SIZE_256T	0x2f
#define TZC_REGION_SIZE_512T	0x30
#define TZC_REGION_SIZE_1P	0x31
#define TZC_REGION_SIZE_2P	0x32
#define TZC_REGION_SIZE_4P	0x33
#define TZC_REGION_SIZE_8P	0x34
#define TZC_REGION_SIZE_16P	0x35
#define TZC_REGION_SIZE_32P	0x36
#define TZC_REGION_SIZE_64P	0x37
#define TZC_REGION_SIZE_128P	0x38
#define TZC_REGION_SIZE_256P	0x39
#define TZC_REGION_SIZE_512P	0x3a
#define TZC_REGION_SIZE_1E	0x3b
#define TZC_REGION_SIZE_2E	0x3c
#define TZC_REGION_SIZE_4E	0x3d
#define TZC_REGION_SIZE_8E	0x3e
#define TZC_REGION_SIZE_16E	0x3f

#define TZC_REGION_SIZE_SHIFT	0x1
#define TZC_REGION_SIZE_MASK	GENMASK_32(6, 1)
#define TZC_ATTR_REGION_SIZE(s)	((s) << TZC_REGION_SIZE_SHIFT)

#define TZC_SUBREGION_DIS_SHIFT	8
#define TZC_SUBREGION_DIS_MASK	GENMASK_32(15, 8)
#define TZC_ATTR_SUBREGION_DIS(subreg) \
	(BIT((subreg) + TZC_SUBREGION_DIS_SHIFT) & \
	 TZC_SUBREGION_DIS_MASK)

#define TZC_ATTR_REGION_EN_SHIFT	0x0
#define TZC_ATTR_REGION_EN_MASK		0x1

#define TZC_ATTR_REGION_EN
#define TZC_ATTR_REGION_ENABLE	0x1
#define TZC_ATTR_REGION_DISABLE	0x0

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
