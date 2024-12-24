/* SPDX-License-Identifier: (BSD-2-Clause AND BSD-3-Clause) */
/*
 * Copyright (c) 2024, Telechips Inc.
 */

#ifndef __DRIVERS_TCC_OMC_H
#define __DRIVERS_TCC_OMC_H

#include <stdint.h>
#include <types_ext.h>
#include <trace_levels.h>
#include <tee_api_types.h>
#include <util.h>

#define ACTION_OFF		U(0x1004)

#define INT_STATUS		U(0x1010)
#define INT_CLEAR		U(0x1014)
#define FAIL_ADDRESS_LOW_OFF	U(0x1020)
#define FAIL_ADDRESS_HIGH_OFF	U(0x1024)
#define FAIL_CONTROL_OFF	U(0x1028)
#define FAIL_ID_OFF		U(0x102c)
#define FAIL_DIRECTION_OFF(d)	(U(0x20) * (d))

#define REGION_BASE_LOW_OFF	U(0x1100)
#define REGION_BASE_HIGH_OFF	U(0x1104)
#define REGION_TOP_LOW_OFF	U(0x1108)
#define REGION_TOP_HIGH_OFF	U(0x110c)
#define REGION_ATTRIBUTES_OFF	U(0x1110)
#define REGION_ID_ACCESS_OFF	U(0x1114)
#define REGION_NUM_OFF(region)  (U(0x20) * (region))

#define ADDRESS_CTRL0_OFF	U(0x1f00)
#define ADDRESS_CTRL1_OFF	U(0x1f04)
#define REGION0_START_OFF	U(0x1f10)
#define REGION0_END_OFF		U(0x1f14)
#define REGION0_CFG_OFF		U(0x1f18)
#define REGION1_START_OFF	U(0x1f20)
#define REGION1_END_OFF		U(0x1f24)
#define REGION1_CFG_OFF		U(0x1f28)
#define CHIP0_SIZE_OFF		U(0x1f30)
#define CHIP1_SIZE_OFF		U(0x1f34)

#define OMC_INT_READ		U(0)
#define OMC_INT_WRITE		U(1)
#define OMC_INT_MAX		U(2)

#define INT_STATUS_OVERLAP	BIT(16)
#define INT_STATUS_OVERRUN	BIT(8)
#define INT_STATUS_STATUS	BIT(0)

#define INT_CLEAR_CLEAR_SHIFT	U(0)
#define INT_CLEAR_CLEAR_MASK	U(0x1)

/* If set non-secure access, else secure access */
#define FAIL_CONTROL_NONSECURE	BIT(21)
/* If set privileged access, else unprivileged access */
#define FAIL_CONTROL_PRIVILEGED	BIT(20)

#define FAIL_ID_AID_SHIFT	U(8)
#define FAIL_ID_AID_MASK	U(0xfffff)
#define FAIL_ID_MID_SHIFT	U(0)
#define FAIL_ID_MID_MASK	U(0xff)

/* Used along with 'enum tzc_region_attributes' below */
#define REG_ATTR_SEC_SHIFT	U(30)
#define REG_ATTR_F_EN_SHIFT	U(0)
#define REG_ATTR_F_EN_MASK	U(0x1)

#define REGION_ID_ACCESS_NSAID_WR_EN_SHIFT	U(16)
#define REGION_ID_ACCESS_NSAID_RD_EN_SHIFT	U(0)
#define REGION_ID_ACCESS_NSAID_ID_MASK		U(0xf)

/* Macros for setting Region ID access permissions based on NSAID */
#define TZC_REGION_ACCESS_RD(id)					\
		SHIFT_U32(BIT((id) & REGION_ID_ACCESS_NSAID_ID_MASK), \
			  REGION_ID_ACCESS_NSAID_RD_EN_SHIFT)
#define TZC_REGION_ACCESS_WR(id)					\
		SHIFT_U32(BIT((id) & REGION_ID_ACCESS_NSAID_ID_MASK), \
			  REGION_ID_ACCESS_NSAID_WR_EN_SHIFT)

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

void omc_init(vaddr_t base, uint32_t size, uint8_t num);
void omc_configure_region(uint8_t region, const struct tzc_region_config *cfg);
TEE_Result omc_get_region_config(uint8_t region, struct tzc_region_config *cfg);
void omc_set_action(enum tzc_action action);

void omc_fail_dump(uint8_t filter);
void omc_int_clear(uint8_t filter);

#endif /* __DRIVERS_TCC_OMC_H */
