// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2026, STMicroelectronics - All Rights Reserved
 */

#include <assert.h>
#include <config.h>
#include <console.h>
#include <drivers/regulator.h>
#include <drivers/stm32_i2c.h>
#include <drivers/stpmic2.h>
#include <dt-bindings/mfd/st,stpmic2.h>
#include <kernel/boot.h>
#include <kernel/delay.h>
#include <kernel/dt.h>
#include <kernel/interrupt.h>
#include <kernel/notif.h>
#include <kernel/panic.h>
#include <kernel/pm.h>
#include <libfdt.h>
#include <platform_config.h>
#include <stdbool.h>
#include <stdint.h>
#include <stm32mp_pm.h>
#include <string.h>
#include <trace.h>
#include <util.h>

enum {
	STPMIC2_BUCK1 = 0,
	STPMIC2_BUCK1H,
	STPMIC2_BUCK2,
	STPMIC2_BUCK3,
	STPMIC2_BUCK4,
	STPMIC2_BUCK5,
	STPMIC2_BUCK6,
	STPMIC2_BUCK7,
	STPMIC2_REFDDR,
	STPMIC2_LDO1,
	STPMIC2_LDO2,
	STPMIC2_LDO3,
	STPMIC2_LDO4,
	STPMIC2_LDO5,
	STPMIC2_LDO6,
	STPMIC2_LDO7,
	STPMIC2_LDO8,
	STPMIC2_GPO1,
	STPMIC2_GPO2,
	STPMIC2_GPO3,
	STPMIC2_GPO4,
	STPMIC2_GPO5,
	STPMIC2_NB_REG,
};

/* Status Registers */
#define PRODUCT_ID		U(0x00)
#define VERSION_SR		U(0x01)
#define TURN_ON_SR		U(0x02)
#define TURN_OFF_SR		U(0x03)
#define RESTART_SR		U(0x04)
#define OCP_SR1			U(0x05)
#define OCP_SR2			U(0x06)
#define EN_SR1			U(0x07)
#define EN_SR2			U(0x08)
#define FS_CNT_SR1		U(0x09)
#define FS_CNT_SR2		U(0x0A)
#define FS_CNT_SR3		U(0x0B)
#define MODE_SR			U(0x0C)
/* Control Registers */
#define MAIN_CR			U(0x10)
#define VINLOW_CR		U(0x11)
#define PKEY_LKP_CR		U(0x12)
#define WDG_CR			U(0x13)
#define WDG_TMR_CR		U(0x14)
#define WDG_TMR_SR		U(0x15)
#define FS_OCP_CR1		U(0x16)
#define FS_OCP_CR2		U(0x17)
#define PADS_PULL_CR		U(0x18)
#define BUCKS_PD_CR1		U(0x19)
#define BUCKS_PD_CR2		U(0x1A)
#define LDOS_PD_CR1		U(0x1B)
#define LDOS_PD_CR2		U(0x1C)
#define GPO_MRST_CR		U(0x1C)
#define BUCKS_MRST_CR		U(0x1D)
#define LDOS_MRST_CR		U(0x1E)
/* Buck CR */
#define BUCK1_MAIN_CR1		U(0x20)
#define BUCK1_MAIN_CR2		U(0x21)
#define BUCK1_ALT_CR1		U(0x22)
#define BUCK1_ALT_CR2		U(0x23)
#define BUCK1_PWRCTRL_CR	U(0x24)
#define BUCK2_MAIN_CR1		U(0x25)
#define BUCK2_MAIN_CR2		U(0x26)
#define BUCK2_ALT_CR1		U(0x27)
#define BUCK2_ALT_CR2		U(0x28)
#define BUCK2_PWRCTRL_CR	U(0x29)
#define BUCK3_MAIN_CR1		U(0x2A)
#define BUCK3_MAIN_CR2		U(0x2B)
#define BUCK3_ALT_CR1		U(0x2C)
#define BUCK3_ALT_CR2		U(0x2D)
#define BUCK3_PWRCTRL_CR	U(0x2E)
#define BUCK4_MAIN_CR1		U(0x2F)
#define BUCK4_MAIN_CR2		U(0x30)
#define BUCK4_ALT_CR1		U(0x31)
#define BUCK4_ALT_CR2		U(0x32)
#define BUCK4_PWRCTRL_CR	U(0x33)
#define BUCK5_MAIN_CR1		U(0x34)
#define BUCK5_MAIN_CR2		U(0x35)
#define BUCK5_ALT_CR1		U(0x36)
#define BUCK5_ALT_CR2		U(0x37)
#define BUCK5_PWRCTRL_CR	U(0x38)
#define BUCK6_MAIN_CR1		U(0x39)
#define BUCK6_MAIN_CR2		U(0x3A)
#define BUCK6_ALT_CR1		U(0x3B)
#define BUCK6_ALT_CR2		U(0x3C)
#define BUCK6_PWRCTRL_CR	U(0x3D)
#define BUCK7_MAIN_CR1		U(0x3E)
#define BUCK7_MAIN_CR2		U(0x3F)
#define BUCK7_ALT_CR1		U(0x40)
#define BUCK7_ALT_CR2		U(0x41)
#define BUCK7_PWRCTRL_CR	U(0x42)
/* GPO CR used only on STPMIC1L and STPMIC2L*/
#define GPO1_MAIN_CR		U(0x43)
#define GPO1_ALT_CR		U(0x44)
#define GPO1_PWRCTRL_CR		U(0x45)
#define GPO2_MAIN_CR		U(0x46)
#define GPO2_ALT_CR		U(0x47)
#define GPO2_PWRCTRL_CR		U(0x48)
/* LDO CR */
#define LDO1_MAIN_CR		U(0x4C)
#define LDO1_ALT_CR		U(0x4D)
#define LDO1_PWRCTRL_CR		U(0x4E)
#define LDO2_MAIN_CR		U(0x4F)
#define LDO2_ALT_CR		U(0x50)
#define LDO2_PWRCTRL_CR		U(0x51)
#define LDO3_MAIN_CR		U(0x52)
#define LDO3_ALT_CR		U(0x53)
#define LDO3_PWRCTRL_CR		U(0x54)
#define LDO4_MAIN_CR		U(0x55)
#define LDO4_ALT_CR		U(0x56)
#define LDO4_PWRCTRL_CR		U(0x57)
#define LDO5_MAIN_CR		U(0x58)
#define LDO5_ALT_CR		U(0x59)
#define LDO5_PWRCTRL_CR		U(0x5A)
#define LDO6_MAIN_CR		U(0x5B)
#define LDO6_ALT_CR		U(0x5C)
#define LDO6_PWRCTRL_CR		U(0x5D)
#define LDO7_MAIN_CR		U(0x5E)
#define LDO7_ALT_CR		U(0x5F)
#define LDO7_PWRCTRL_CR		U(0x60)
#define LDO8_MAIN_CR		U(0x61)
#define LDO8_ALT_CR		U(0x62)
#define LDO8_PWRCTRL_CR		U(0x63)
#define REFDDR_MAIN_CR		U(0x64)
#define REFDDR_ALT_CR		U(0x65)
#define REFDDR_PWRCTRL_CR	U(0x66)
/* GPO CR used only on STPMIC1L and STPMIC2L*/
#define GPO3_MAIN_CR		U(0x67)
#define GPO3_ALT_CR		U(0x68)
#define GPO3_PWRCTRL_CR		U(0x69)
#define GPO4_MAIN_CR		U(0x6A)
#define GPO4_ALT_CR		U(0x6B)
#define GPO4_PWRCTRL_CR		U(0x6C)
#define GPO5_MAIN_CR		U(0x6D)
#define GPO5_ALT_CR		U(0x6E)
#define GPO5_PWRCTRL_CR		U(0x6F)
/* INTERRUPT CR */
#define INT_PENDING_R1		U(0x70)
#define INT_PENDING_R2		U(0x71)
#define INT_PENDING_R3		U(0x72)
#define INT_PENDING_R4		U(0x73)
#define INT_CLEAR_R1		U(0x74)
#define INT_CLEAR_R2		U(0x75)
#define INT_CLEAR_R3		U(0x76)
#define INT_CLEAR_R4		U(0x77)
#define INT_MASK_R1		U(0x78)
#define INT_MASK_R2		U(0x79)
#define INT_MASK_R3		U(0x7A)
#define INT_MASK_R4		U(0x7B)
#define INT_SRC_R1		U(0x7C)
#define INT_SRC_R2		U(0x7D)
#define INT_SRC_R3		U(0x7E)
#define INT_SRC_R4		U(0x7F)
#define INT_DBG_LATCH_R1	U(0x80)
#define INT_DBG_LATCH_R2	U(0x81)
#define INT_DBG_LATCH_R3	U(0x82)
#define INT_DBG_LATCH_R4	U(0x83)

/* NVMEM shadow registers */
#define NVM_BUCK1_VOUT_SHR	U(0x9C)

/* PRODUCT_ID bits definition */
#define PMIC_NVM_ID_MASK	GENMASK_32(3, 0)
#define PMIC_REF_ID_MASK	GENMASK_32(7, 4)
#define PMIC_REF_ID_SHIFT	4
#define PMIC_REF_ID_STPMIC1L	U(1)
#define PMIC_REF_ID_STPMIC25	U(2)
#define PMIC_REF_ID_STPMIC2L	U(3)

/* VERSION_SR bits definition */
#define MINOR_VERSION_MASK	GENMASK_32(3, 0)
#define MAJOR_VERSION_MASK	GENMASK_32(7, 4)
#define MAJOR_VERSION_SHIFT	4

/* MAIN_CR bits definition */
#define MAIN_CR_SWOFF		BIT(0)

/* BUCKS_MRST_CR bits definition */
#define BUCK1_MRST		BIT(0)
#define BUCK2_MRST		BIT(1)
#define BUCK3_MRST		BIT(2)
#define BUCK4_MRST		BIT(3)
#define BUCK5_MRST		BIT(4)
#define BUCK6_MRST		BIT(5)
#define BUCK7_MRST		BIT(6)
#define REFDDR_MRST		BIT(7)

/* LDOS_MRST_CR bits definition */
#define LDO1_MRST		BIT(0)
#define LDO2_MRST		BIT(1)
#define LDO3_MRST		BIT(2)
#define LDO4_MRST		BIT(3)
#define LDO5_MRST		BIT(4)
#define LDO6_MRST		BIT(5)
#define LDO7_MRST		BIT(6)
#define LDO8_MRST		BIT(7)

/* GPO_MRST_CR bits definition */
#define GPO1_MRST		BIT(1)
#define GPO2_MRST		BIT(2)
#define GPO3_MRST		BIT(3)
#define GPO4_MRST		BIT(4)
#define GPO5_MRST		BIT(5)

/* LDOx_MAIN_CR */
#define LDO_VOLT_SHIFT		1
#define LDO_BYPASS		BIT(6)
#define LDO1_INPUT_SRC		BIT(7)
#define LDO3_SNK_SRC		BIT(7)
#define LDO4_INPUT_SRC_SHIFT	6
#define LDO4_INPUT_SRC_MASK	GENMASK_32(7, 6)

/* PWRCTRL register bit definition */
#define PWRCTRL_EN		BIT(0)
#define PWRCTRL_RS		BIT(1)
#define PWRCTRL_SEL_SHIFT	2
#define PWRCTRL_SEL_MASK	GENMASK_32(3, 2)

/* BUCKx_MAIN_CR2 */
#define PREG_MODE_SHIFT		1
#define PREG_MODE_MASK		GENMASK_32(2, 1)

/* BUCKS_PD_CR1 */
#define BUCK1_PD_MASK		GENMASK_32(1, 0)
#define BUCK2_PD_MASK		GENMASK_32(3, 2)
#define BUCK3_PD_MASK		GENMASK_32(5, 4)
#define BUCK4_PD_MASK		GENMASK_32(7, 6)

#define BUCK1_PD_FAST		BIT(1)
#define BUCK2_PD_FAST		BIT(3)
#define BUCK3_PD_FAST		BIT(5)
#define BUCK4_PD_FAST		BIT(7)

/* BUCKS_PD_CR2 */
#define BUCK5_PD_MASK		GENMASK_32(1, 0)
#define BUCK6_PD_MASK		GENMASK_32(3, 2)
#define BUCK7_PD_MASK		GENMASK_32(5, 4)

#define BUCK5_PD_FAST		BIT(1)
#define BUCK6_PD_FAST		BIT(3)
#define BUCK7_PD_FAST		BIT(5)

/* LDOS_PD_CR1 */
#define LDO1_PD			BIT(0)
#define LDO2_PD			BIT(1)
#define LDO3_PD			BIT(2)
#define LDO4_PD			BIT(3)
#define LDO5_PD			BIT(4)
#define LDO6_PD			BIT(5)
#define LDO7_PD			BIT(6)
#define LDO8_PD			BIT(7)

/* LDOS_PD_CR2 */
#define REFDDR_PD		BIT(0)

/* FS_OCP_CR1 */
#define FS_OCP_BUCK1		BIT(0)
#define FS_OCP_BUCK2		BIT(1)
#define FS_OCP_BUCK3		BIT(2)
#define FS_OCP_BUCK4		BIT(3)
#define FS_OCP_BUCK5		BIT(4)
#define FS_OCP_BUCK6		BIT(5)
#define FS_OCP_BUCK7		BIT(6)
#define FS_OCP_REFDDR		BIT(7)

/* FS_OCP_CR2 */
#define FS_OCP_LDO1		BIT(0)
#define FS_OCP_LDO2		BIT(1)
#define FS_OCP_LDO3		BIT(2)
#define FS_OCP_LDO4		BIT(3)
#define FS_OCP_LDO5		BIT(4)
#define FS_OCP_LDO6		BIT(5)
#define FS_OCP_LDO7		BIT(6)
#define FS_OCP_LDO8		BIT(7)

/* NVM_BUCK1_VOUT_SHR */
#define BUCK1_VRANGE_CFG	BIT(7)

enum stpmic2_prop_id {
	STPMIC2_MASK_RESET = 0,
	STPMIC2_PULL_DOWN,
	STPMIC2_BYPASS,
	STPMIC2_SINK_SOURCE,
	STPMIC2_OCP,
	STPMIC2_PWRCTRL_EN,
	STPMIC2_PWRCTRL_RS,
	STPMIC2_PWRCTRL_SEL,	/* takes arg = pwrctrl line number */
	STPMIC2_MAIN_PREG_MODE,	/* takes arg = preg mode HP=1, CCM=2 */
	STPMIC2_ALT_PREG_MODE,	/* takes arg = preg mode HP=1, CCM=2 */
	STPMIC2_ALTERNATE_INPUT_SOURCE,
};

#define PROP_BYPASS_RESET	U(0)
#define PROP_BYPASS_SET		U(1)

/*
 * struct stpmic2 - STPMIC2 device instance
 */
struct stpmic2 {
	const void *compat_data;
	struct i2c_handle_s *i2c_handle;
	uint16_t i2c_addr;
	uint8_t ref_id;
	bool system_power_controller;
};

#define VOLTAGE_INDEX_INVALID		((size_t)~(U(0)))

struct regul_struct {
	const char *name;
	const uint16_t *volt_table;
	uint8_t volt_table_size;
	uint8_t volt_cr;
	uint8_t volt_shift;
	uint8_t en_cr;
	uint8_t alt_en_cr;
	uint8_t alt_volt_cr;
	uint8_t pwrctrl_cr;
	uint8_t msrt_reg;
	uint8_t msrt_mask;
	uint8_t pd_reg;
	uint8_t pd_val;
	uint8_t pd_mask;
	uint8_t ocp_reg;
	uint8_t ocp_mask;
};

#define BUCK_VOLT_TABLE_SIZE 128
#define LDO235678_VOLT_TABLE_SIZE 32
#define LDO_SINGLE_VOLT_TABLE_SIZE 1

/* Voltage tables in mV */
static const uint16_t buck_low_volt_table[BUCK_VOLT_TABLE_SIZE] = {
	U(500), U(510), U(520), U(530), U(540),
	U(550), U(560), U(570), U(580), U(590),
	U(600), U(610), U(620), U(630), U(640),
	U(650), U(660), U(670), U(680), U(690),
	U(700), U(710), U(720), U(730), U(740),
	U(750), U(760), U(770), U(780), U(790),
	U(800), U(810), U(820), U(830), U(840),
	U(850), U(860), U(870), U(880), U(890),
	U(900), U(910), U(920), U(930), U(940),
	U(950), U(960), U(970), U(980), U(990),
	U(1000), U(1010), U(1020), U(1030), U(1040),
	U(1050), U(1060), U(1070), U(1080), U(1090),
	U(1100), U(1110), U(1120), U(1130), U(1140),
	U(1150), U(1160), U(1170), U(1180), U(1190),
	U(1200), U(1210), U(1220), U(1230), U(1240),
	U(1250), U(1260), U(1270), U(1280), U(1290),
	U(1300), U(1310), U(1320), U(1330), U(1340),
	U(1350), U(1360), U(1370), U(1380), U(1390),
	U(1400), U(1410), U(1420), U(1430), U(1440),
	U(1450), U(1460), U(1470), U(1480), U(1490),
	U(1500), U(1500), U(1500), U(1500), U(1500),
	U(1500), U(1500), U(1500), U(1500), U(1500),
	U(1500), U(1500), U(1500), U(1500), U(1500),
	U(1500), U(1500), U(1500), U(1500), U(1500),
	U(1500), U(1500), U(1500), U(1500), U(1500),
	U(1500), U(1500), U(1500)
};

static const uint16_t buck_high_volt_table[BUCK_VOLT_TABLE_SIZE] = {
	U(1500), U(1500), U(1500), U(1500), U(1500),
	U(1500), U(1500), U(1500), U(1500), U(1500),
	U(1500), U(1500), U(1500), U(1500), U(1500),
	U(1500), U(1500), U(1500), U(1500), U(1500),
	U(1500), U(1500), U(1500), U(1500), U(1500),
	U(1500), U(1500), U(1500), U(1500), U(1500),
	U(1500), U(1500), U(1500), U(1500), U(1500),
	U(1500), U(1500), U(1500), U(1500), U(1500),
	U(1500), U(1500), U(1500), U(1500), U(1500),
	U(1500), U(1500), U(1500), U(1500), U(1500),
	U(1500), U(1500), U(1500), U(1500), U(1500),
	U(1500), U(1500), U(1500), U(1500), U(1500),
	U(1500), U(1500), U(1500), U(1500), U(1500),
	U(1500), U(1500), U(1500), U(1500), U(1500),
	U(1500), U(1500), U(1500), U(1500), U(1500),
	U(1500), U(1500), U(1500), U(1500), U(1500),
	U(1500), U(1500), U(1500), U(1500), U(1500),
	U(1500), U(1500), U(1500), U(1500), U(1500),
	U(1500), U(1500), U(1500), U(1500), U(1500),
	U(1500), U(1500), U(1500), U(1500), U(1500),
	U(1500), U(1600), U(1700), U(1800), U(1900),
	U(2000), U(2100), U(2200), U(2300), U(2400),
	U(2500), U(2600), U(2700), U(2800), U(2900),
	U(3000), U(3100), U(3200), U(3300), U(3400),
	U(3500), U(3600), U(3700), U(3800), U(3900),
	U(4000), U(4100), U(4200)
};

static const uint16_t ldo235678_volt_table[LDO235678_VOLT_TABLE_SIZE] = {
	U(900), U(1000), U(1100), U(1200), U(1300),
	U(1400), U(1500), U(1600), U(1700), U(1800),
	U(1900), U(2000), U(2100), U(2200), U(2300),
	U(2400), U(2500), U(2600), U(2700), U(2800),
	U(2900), U(3000), U(3100), U(3200), U(3300),
	U(3400), U(3500), U(3600), U(3700), U(3800),
	U(3900), U(4000)
};

static const uint16_t ldo1_volt_table[LDO_SINGLE_VOLT_TABLE_SIZE] = {
	U(1800),
};

static const uint16_t ldo4_volt_table[LDO_SINGLE_VOLT_TABLE_SIZE] = {
	U(3300),
};

static const uint16_t refddr_volt_table[LDO_SINGLE_VOLT_TABLE_SIZE] = {
	U(0),
};

#define DEFINE_BUCK(regu_name, ID, pd, table) { \
	.name			= regu_name, \
	.volt_table		= table, \
	.volt_table_size	= BUCK_VOLT_TABLE_SIZE, \
	.en_cr			= ID ## _MAIN_CR2, \
	.volt_cr		= ID ## _MAIN_CR1, \
	.alt_en_cr		= ID ## _ALT_CR2, \
	.alt_volt_cr		= ID ## _ALT_CR1, \
	.pwrctrl_cr		= ID ## _PWRCTRL_CR, \
	.msrt_reg		= BUCKS_MRST_CR, \
	.msrt_mask		= ID ## _MRST, \
	.pd_reg			= pd, \
	.pd_val			= ID ## _PD_FAST, \
	.pd_mask		= ID ## _PD_MASK, \
	.ocp_reg		= FS_OCP_CR1, \
	.ocp_mask		= FS_OCP_ ## ID, \
}

#define DEFINE_LDOx(regu_name, ID, table, size) { \
	.name			= regu_name, \
	.volt_table		= table, \
	.volt_table_size	= size, \
	.volt_shift		= LDO_VOLT_SHIFT, \
	.en_cr			= ID ## _MAIN_CR, \
	.volt_cr		= ID ## _MAIN_CR, \
	.alt_en_cr		= ID ## _ALT_CR, \
	.alt_volt_cr		= ID ## _ALT_CR, \
	.pwrctrl_cr		= ID ## _PWRCTRL_CR, \
	.msrt_reg		= LDOS_MRST_CR, \
	.msrt_mask		= ID ## _MRST, \
	.pd_reg			= LDOS_PD_CR1, \
	.pd_val			= ID ## _PD, \
	.pd_mask		= ID ## _PD, \
	.ocp_reg		= FS_OCP_CR2, \
	.ocp_mask		= FS_OCP_ ## ID, \
}

#define DEFINE_REFDDR(regu_name, ID, table) { \
	.name			= regu_name, \
	.volt_table		= table, \
	.volt_table_size	= LDO_SINGLE_VOLT_TABLE_SIZE, \
	.en_cr			= ID ## _MAIN_CR, \
	.volt_cr		= ID ## _MAIN_CR, \
	.alt_en_cr		= ID ## _ALT_CR, \
	.alt_volt_cr		= ID ## _ALT_CR, \
	.pwrctrl_cr		= ID ## _PWRCTRL_CR, \
	.msrt_reg		= BUCKS_MRST_CR, \
	.msrt_mask		= ID ## _MRST, \
	.pd_reg			= LDOS_PD_CR2, \
	.pd_val			= ID ## _PD, \
	.pd_mask		= ID ## _PD, \
	.ocp_reg		= FS_OCP_CR1, \
	.ocp_mask		= FS_OCP_ ## ID, \
}

#define DEFINE_GPOx(regu_name, ID) { \
	.name			= regu_name, \
	.en_cr			= ID ## _MAIN_CR, \
	.alt_en_cr		= ID ## _ALT_CR, \
	.pwrctrl_cr		= ID ## _PWRCTRL_CR, \
	.msrt_reg		= GPO_MRST_CR, \
	.msrt_mask		= ID ## _MRST, \
}

/* Table of Regulators in STPMIC2 */
static const struct regul_struct regul_table[] = {
	[STPMIC2_BUCK1] = DEFINE_BUCK("buck1", BUCK1, BUCKS_PD_CR1,
				      buck_low_volt_table),
	[STPMIC2_BUCK1H] = DEFINE_BUCK("buck1h", BUCK1, BUCKS_PD_CR1,
				      buck_high_volt_table),
	[STPMIC2_BUCK2] = DEFINE_BUCK("buck2", BUCK2, BUCKS_PD_CR1,
				      buck_low_volt_table),
	[STPMIC2_BUCK3] = DEFINE_BUCK("buck3", BUCK3, BUCKS_PD_CR1,
				      buck_low_volt_table),
	[STPMIC2_BUCK4] = DEFINE_BUCK("buck4", BUCK4, BUCKS_PD_CR1,
				      buck_high_volt_table),
	[STPMIC2_BUCK5] = DEFINE_BUCK("buck5", BUCK5, BUCKS_PD_CR2,
				      buck_high_volt_table),
	[STPMIC2_BUCK6] = DEFINE_BUCK("buck6", BUCK6, BUCKS_PD_CR2,
				      buck_low_volt_table),
	[STPMIC2_BUCK7] = DEFINE_BUCK("buck7", BUCK7, BUCKS_PD_CR2,
				      buck_high_volt_table),

	[STPMIC2_REFDDR] = DEFINE_REFDDR("refddr", REFDDR, refddr_volt_table),

	[STPMIC2_LDO1] = DEFINE_LDOx("ldo1", LDO1, ldo1_volt_table,
				     LDO_SINGLE_VOLT_TABLE_SIZE),
	[STPMIC2_LDO2] = DEFINE_LDOx("ldo2", LDO2, ldo235678_volt_table,
				     LDO235678_VOLT_TABLE_SIZE),
	[STPMIC2_LDO3] = DEFINE_LDOx("ldo3", LDO3, ldo235678_volt_table,
				     LDO235678_VOLT_TABLE_SIZE),
	[STPMIC2_LDO4] = DEFINE_LDOx("ldo4", LDO4, ldo4_volt_table,
				     LDO_SINGLE_VOLT_TABLE_SIZE),
	[STPMIC2_LDO5] = DEFINE_LDOx("ldo5", LDO5, ldo235678_volt_table,
				     LDO235678_VOLT_TABLE_SIZE),
	[STPMIC2_LDO6] = DEFINE_LDOx("ldo6", LDO6, ldo235678_volt_table,
				     LDO235678_VOLT_TABLE_SIZE),
	[STPMIC2_LDO7] = DEFINE_LDOx("ldo7", LDO7, ldo235678_volt_table,
				     LDO235678_VOLT_TABLE_SIZE),
	[STPMIC2_LDO8] = DEFINE_LDOx("ldo8", LDO8, ldo235678_volt_table,
				     LDO235678_VOLT_TABLE_SIZE),

	[STPMIC2_GPO1] = DEFINE_GPOx("gpo1", GPO1),
	[STPMIC2_GPO2] = DEFINE_GPOx("gpo2", GPO2),
	[STPMIC2_GPO3] = DEFINE_GPOx("gpo3", GPO3),
	[STPMIC2_GPO4] = DEFINE_GPOx("gpo4", GPO4),
	[STPMIC2_GPO5] = DEFINE_GPOx("gpo5", GPO5),
};

static TEE_Result stpmic2_regulator_get_id(const char *regu_name, uint8_t *id)
{
	uint8_t i = 0;

	FMSG("Stpmic2 get id %s", regu_name);

	for (i = 0; i < ARRAY_SIZE(regul_table); i++)
		if (!strcmp(regul_table[i].name, regu_name)) {
			*id = i;
			return TEE_SUCCESS;
		}

	return TEE_ERROR_ITEM_NOT_FOUND;
}

static TEE_Result stpmic2_register_read(struct stpmic2 *pmic,
					uint8_t register_id, uint8_t *value)
{
	int rc = 0;

	rc = stm32_i2c_read_write_membyte(pmic->i2c_handle,
					  pmic->i2c_addr,
					  register_id, value,
					  false /* !write */);
	if (rc) {
		EMSG("Failed to read register %#"PRIx8, register_id);
		return TEE_ERROR_COMMUNICATION;
	}

	FMSG("REG[%#"PRIx8" v=%#"PRIx8, register_id, *value);

	return TEE_SUCCESS;
}

static TEE_Result stpmic2_register_write(struct stpmic2 *pmic,
					 uint8_t register_id, uint8_t value)
{
	int rc = 0;

	rc = stm32_i2c_read_write_membyte(pmic->i2c_handle,
					  pmic->i2c_addr,
					  register_id, &value,
					  true /* write */);
	if (rc) {
		EMSG("Failed to write reg: %#"PRIx8, register_id);
		return TEE_ERROR_COMMUNICATION;
	}

	FMSG("REG:%#"PRIx8" written v=%#"PRIx8, register_id, value);

	return TEE_SUCCESS;
}

static TEE_Result stpmic2_register_update(struct stpmic2 *pmic,
					  uint8_t register_id, uint8_t value,
					  uint8_t mask)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint8_t val = 0;

	res = stpmic2_register_read(pmic, register_id, &val);
	if (res)
		return res;

	val = (val & ~mask) | (value & mask);

	FMSG("REG:%#"PRIx8" v=%#"PRIx8" mask=%#"PRIx8" -> %#"PRIx8,
	     register_id, value, mask, val);

	return stpmic2_register_write(pmic, register_id, val);
}

static TEE_Result stpmic2_regulator_set_state(struct stpmic2 *pmic, uint8_t id,
					      bool enable)
{
	const struct regul_struct *regul = regul_table + id;

	if (enable)
		return stpmic2_register_update(pmic, regul->en_cr, 1, 1);
	else
		return stpmic2_register_update(pmic, regul->en_cr, 0, 1);
}

static TEE_Result stpmic2_regulator_get_state(struct stpmic2 *pmic,
					      uint8_t id, bool *enabled)
{
	const struct regul_struct *regul = regul_table + id;
	TEE_Result res = TEE_ERROR_GENERIC;
	uint8_t val = 0;

	res = stpmic2_register_read(pmic, regul->en_cr, &val);
	if (res)
		return res;

	*enabled = val & 1;

	return TEE_SUCCESS;
}

static TEE_Result stpmic2_regulator_levels_mv(struct stpmic2 *pmic __unused,
					      uint8_t id,
					      const uint16_t **levels,
					      size_t *levels_count)
{
	const struct regul_struct *regul = regul_table + id;

	if (levels_count)
		*levels_count = regul->volt_table_size;
	if (levels)
		*levels = regul->volt_table;

	return TEE_SUCCESS;
}

static TEE_Result stpmic2_regulator_get_voltage(struct stpmic2 *pmic,
						uint8_t id, uint16_t *val)
{
	const struct regul_struct *regul = regul_table + id;
	uint8_t value = 0;
	uint8_t mask = 0;

	if (!regul->volt_table_size)
		return TEE_ERROR_GENERIC;

	/* Voltage table size must be a power of 2 to be used as a bitmask */
	assert((regul->volt_table_size & (regul->volt_table_size - 1)) == 0);

	mask = regul->volt_table_size - 1;
	if (mask) {
		TEE_Result res = stpmic2_register_read(pmic, regul->volt_cr,
						       &value);
		if (res)
			return res;

		value = (value >> regul->volt_shift) & mask;
	}

	*val = regul->volt_table[value];

	return TEE_SUCCESS;
}

static size_t voltage_to_index(const struct regul_struct *regul,
			       uint16_t millivolts)
{
	unsigned int i = 0;

	assert(regul->volt_table);
	for (i = 0; i < regul->volt_table_size; i++)
		if (regul->volt_table[i] == millivolts)
			return i;

	return VOLTAGE_INDEX_INVALID;
}

static TEE_Result stpmic2_regulator_set_voltage(struct stpmic2 *pmic,
						uint8_t id, uint16_t millivolts)
{
	const struct regul_struct *regul = regul_table + id;
	size_t index = 0;
	uint8_t mask = 0;

	if (!regul->volt_table_size)
		return TEE_SUCCESS;

	/* Voltage table size must be a power of 2 to be used as a bitmask */
	assert((regul->volt_table_size & (regul->volt_table_size - 1)) == 0);

	mask = regul->volt_table_size - 1;

	index = voltage_to_index(regul, millivolts);
	if (index == VOLTAGE_INDEX_INVALID)
		return TEE_ERROR_BAD_PARAMETERS;

	return stpmic2_register_update(pmic, regul->volt_cr,
				       index << regul->volt_shift,
				       mask << regul->volt_shift);
}

/* update both normal and alternate register */
static TEE_Result stpmic2_update_en_crs(struct stpmic2 *pmic, uint8_t id,
					uint8_t value, uint8_t mask)
{
	const struct regul_struct *regul = regul_table + id;
	TEE_Result res = TEE_ERROR_GENERIC;

	res = stpmic2_register_update(pmic, regul->en_cr, value, mask);
	if (res)
		return res;

	return stpmic2_register_update(pmic, regul->alt_en_cr, value, mask);
}

static TEE_Result stpmic2_regulator_get_prop(struct stpmic2 *pmic, uint8_t id,
					     enum stpmic2_prop_id prop,
					     uint8_t *arg)
{
	const struct regul_struct *regul = regul_table + id;
	TEE_Result res = TEE_ERROR_GENERIC;
	uint8_t val = 0;

	DMSG("%s: get prop %d", regul->name, prop);

	switch (prop) {
	case STPMIC2_BYPASS:
		*arg = PROP_BYPASS_RESET;

		if (id <= STPMIC2_BUCK7 || id == STPMIC2_LDO1 ||
		    id == STPMIC2_LDO4 || id == STPMIC2_REFDDR ||
		    pmic->ref_id != PMIC_REF_ID_STPMIC25)
			return TEE_SUCCESS;

		res = stpmic2_register_read(pmic, regul->en_cr, &val);
		if (res)
			return res;

		if (val & LDO_BYPASS)
			*arg = PROP_BYPASS_SET;

		break;
	default:
		EMSG("Invalid prop %d", prop);
		panic();
	}

	return TEE_SUCCESS;
}

static TEE_Result stpmic2_regulator_set_prop(struct stpmic2 *pmic, uint8_t id,
					     enum stpmic2_prop_id prop,
					     uint8_t arg)
{
	const struct regul_struct *regul = regul_table + id;
	TEE_Result res = TEE_ERROR_GENERIC;

	DMSG("%s: set prop %d arg=%"PRIu8, regul->name, prop, arg);

	switch (prop) {
	case STPMIC2_PULL_DOWN:
		return stpmic2_register_update(pmic, regul->pd_reg,
					       regul->pd_val,
					       regul->pd_val);
	case STPMIC2_MASK_RESET:
		if (!regul->msrt_mask)
			return TEE_ERROR_BAD_PARAMETERS;
		/* enable mask reset */
		return stpmic2_register_update(pmic, regul->msrt_reg,
					       regul->msrt_mask,
					       regul->msrt_mask);
	case STPMIC2_BYPASS:
		if (id <= STPMIC2_BUCK7 || id == STPMIC2_LDO1 ||
		    id == STPMIC2_LDO4 || id == STPMIC2_REFDDR ||
		    pmic->ref_id != PMIC_REF_ID_STPMIC25)
			return TEE_ERROR_BAD_PARAMETERS;

		/* clear sink source mode */
		if (id == STPMIC2_LDO3) {
			res = stpmic2_update_en_crs(pmic, id, 0, LDO3_SNK_SRC);
			if (res)
				return res;
		}

		/* set or reset bypass mode */
		return stpmic2_update_en_crs(pmic, id,
					     (arg == PROP_BYPASS_SET) ?
					     LDO_BYPASS : 0, LDO_BYPASS);
	case STPMIC2_SINK_SOURCE:
		if (id != STPMIC2_LDO3)
			return TEE_ERROR_BAD_PARAMETERS;

		/* clear bypass mode */
		res = stpmic2_update_en_crs(pmic, id, 0, LDO_BYPASS);
		if (res)
			return res;

		return stpmic2_update_en_crs(pmic, id, LDO3_SNK_SRC,
					     LDO3_SNK_SRC);
	case STPMIC2_OCP:
		if (!regul->ocp_reg)
			return TEE_ERROR_BAD_PARAMETERS;
		/* enable mask reset */
		return stpmic2_register_update(pmic, regul->ocp_reg,
					       U(0), regul->ocp_mask);
	case STPMIC2_PWRCTRL_EN:
		if (!regul->pwrctrl_cr)
			return TEE_ERROR_BAD_PARAMETERS;
		/* set pwrctrl eable, disable pwrctrl reset */
		return stpmic2_register_update(pmic, regul->pwrctrl_cr,
					       PWRCTRL_EN,
					       PWRCTRL_EN | PWRCTRL_RS);
	case STPMIC2_PWRCTRL_RS:
		if (!regul->pwrctrl_cr)
			return TEE_ERROR_BAD_PARAMETERS;
		/* set pwrctrl reset, disable pwrctrl enable */
		return stpmic2_register_update(pmic, regul->pwrctrl_cr,
					       PWRCTRL_RS,
					       PWRCTRL_EN | PWRCTRL_RS);
	case STPMIC2_PWRCTRL_SEL:
		if (!regul->pwrctrl_cr)
			return TEE_ERROR_BAD_PARAMETERS;
		/* select pwr control line */
		return stpmic2_register_update(pmic, regul->pwrctrl_cr,
					       arg << PWRCTRL_SEL_SHIFT,
					       PWRCTRL_SEL_MASK);
	case STPMIC2_MAIN_PREG_MODE:
		/* only a buck has preg mode */
		if (id > STPMIC2_BUCK7)
			return TEE_ERROR_BAD_PARAMETERS;
		if (arg > 2)
			return TEE_ERROR_BAD_PARAMETERS;
		/* set preg mode on BUCKx_MAIN_CR2 */
		return stpmic2_register_update(pmic, regul->en_cr,
					       arg << PREG_MODE_SHIFT,
					       PREG_MODE_MASK);
	case STPMIC2_ALT_PREG_MODE:
		/* only a buck has preg mode */
		if (id > STPMIC2_BUCK7)
			return TEE_ERROR_BAD_PARAMETERS;
		if (arg > 2)
			return TEE_ERROR_BAD_PARAMETERS;
		/* set preg mode on BUCKx_MAIN_CR2 */
		return stpmic2_register_update(pmic, regul->alt_en_cr,
					       arg << PREG_MODE_SHIFT,
					       PREG_MODE_MASK);
	case STPMIC2_ALTERNATE_INPUT_SOURCE:
		if (id != STPMIC2_LDO1)
			return TEE_ERROR_BAD_PARAMETERS;

		return stpmic2_update_en_crs(pmic, id,
					     LDO1_INPUT_SRC, LDO1_INPUT_SRC);
	default:
		EMSG("Invalid prop %d", prop);
		panic();
	}

	return 0;
}

static void stpmic2_dump_regulators(struct stpmic2 *pmic)
{
	size_t i = 0;

	assert(pmic);

	if (CFG_TEE_CORE_LOG_LEVEL < TRACE_DEBUG)
		return;

	for (i = 0; i < ARRAY_SIZE(regul_table); i++) {
		bool state = false;
		uint16_t val = 0;
		uint8_t arg = 0;

		if (!regul_table[i].volt_cr)
			continue;

		stpmic2_regulator_get_voltage(pmic, i, &val);
		stpmic2_regulator_get_state(pmic, i, &state);
		stpmic2_regulator_get_prop(pmic, i, STPMIC2_BYPASS, &arg);

		DMSG("PMIC regul %s: %s%s, %"PRIu16"mV", regul_table[i].name,
		     state ? "EN" : "DIS",
		     arg == PROP_BYPASS_SET ? " BYPASS" : "",  val);
	}
}

static TEE_Result stpmic2_get_version(struct stpmic2 *pmic, uint8_t *val)
{
	return stpmic2_register_read(pmic, VERSION_SR, val);
}

static TEE_Result stpmic2_get_product_id(struct stpmic2 *pmic, uint8_t *val)
{
	return stpmic2_register_read(pmic, PRODUCT_ID, val);
}

static TEE_Result stpmic2_is_buck1_high_voltage(struct stpmic2 *pmic,
						bool *high)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint8_t val = 0;

	if (pmic->ref_id == PMIC_REF_ID_STPMIC25) {
		*high = false;
		return TEE_SUCCESS;
	}

	res = stpmic2_register_read(pmic,  NVM_BUCK1_VOUT_SHR, &val);

	*high = val & BUCK1_VRANGE_CFG;

	return res;
}

/*
 *
 * Low Power
 *
 */
static TEE_Result stpmic2_lp_set_state(struct stpmic2 *pmic, uint8_t id,
				       bool enable)
{
	const struct regul_struct *regul = regul_table + id;

	if (enable)
		return stpmic2_register_update(pmic, regul->alt_en_cr, 1, 1);
	else
		return stpmic2_register_update(pmic, regul->alt_en_cr, 0, 1);
}

static TEE_Result stpmic2_lp_set_voltage(struct stpmic2 *pmic, uint8_t id,
					 uint16_t mv)
{
	const struct regul_struct *regul = regul_table + id;
	size_t index = 0;
	uint8_t mask = 0;

	if (!regul->volt_table_size)
		return TEE_SUCCESS;

	/* Voltage table size must be a power of 2 to be used as a bitmask */
	assert((regul->volt_table_size & (regul->volt_table_size - 1)) == 0);

	mask = regul->volt_table_size - 1;

	index = voltage_to_index(regul, mv);
	if (index == VOLTAGE_INDEX_INVALID)
		return TEE_ERROR_GENERIC;

	return stpmic2_register_update(pmic, regul->alt_volt_cr,
				       index << regul->volt_shift,
				       mask << regul->volt_shift);
}

/* STPMIC2 Software switch-OFF */
static TEE_Result stpmic2_switch_off(struct stpmic2 *pmic)
{
	return stpmic2_register_update(pmic, MAIN_CR, MAIN_CR_SWOFF,
				       MAIN_CR_SWOFF);
}

/*
 *
 * Regulators in OP-TEE
 *
 */

/* I2C transfer trial configuration */
#define PMIC_I2C_TRIALS			U(1)
#define PMIC_I2C_TIMEOUT_BUSY_MS	U(5)

#define STPMIC2_LP_STATE_OFF		BIT(0)
#define STPMIC2_LP_STATE_ON		BIT(1)
#define STPMIC2_LP_STATE_UNMODIFIED	BIT(2)
#define STPMIC2_LP_STATE_SET_VOLT	BIT(3)
#define STPMIC2_LP_STATE_INVALID	-1

/*
 * struct stpmic2_regu - STPMIC2 regulator instance
 *
 * @pmic: Handle to PMIC device
 * @id: ID in PMIC device of the regulator controllers
 * @bypass_uv: 0 if not used, else is the voltage level to switch to bypass mode
 * @lp_state: Regulator mode during PM low power state, per PM states
 * @lp_level_uv: Regulator voltage level during PM low power state, per PM state
 * @last_lp_mode: Last low power mode selected
 * @levels_desc: Description of the supported voltage levels
 * @levels: Voltage level value array related to description @levels_desc
 * @power_control_en: PWRCTRL input line is enabled
 * @forced_off: Regulator was forced off at suspend
 */
struct stpmic2_regu {
	struct stpmic2 *pmic;
	uint32_t id;
	int bypass_uv;
	uint8_t *lp_state;
	int *lp_level_uv;
	int last_lp_mode;
	struct regulator_voltages_desc levels_desc;
	int *levels;
	bool power_control_en;
	bool forced_off;
};

/*
 * struct stpmic2_compat_data - pmic specificity helper
 * @desc_table: description table of each regulator
 * @desc_len: len of the description table
 * @ref_id: value of PMIC_REF_ID in PRODUCT_ID_SR
 */
struct stpmic2_compat_data {
	const struct regu_dt_desc *desc_table;
	size_t desc_len;
	uint8_t ref_id;
};

/*
 * struct stpmic2_regu_dt_property - DT property helper
 * @name: DT property string name
 * @prop: Property decimal identifier
 */
struct stpmic2_regu_dt_property {
	const char *name;
	enum stpmic2_prop_id prop;
};

static const struct stpmic2_regu_dt_property prop_table[] = {
	{
		.name = "st,mask-reset",
		.prop = STPMIC2_MASK_RESET,
	},
	{
		.name = "st,pwrctrl-enable",
		.prop = STPMIC2_PWRCTRL_EN,
	},
	{
		.name = "st,pwrctrl-reset",
		.prop = STPMIC2_PWRCTRL_RS,
	},
	{
		.name = "st,pwrctrl-sel",
		.prop = STPMIC2_PWRCTRL_SEL,
	},
	{
		.name = "st,alternate-input-source",
		.prop = STPMIC2_ALTERNATE_INPUT_SOURCE,
	},
};

static void stpmic2_lock_unlock(bool lock_not_unlock)
{
	static struct mutex pmic_mu = MUTEX_INITIALIZER;

	if (thread_get_id_may_fail() != THREAD_ID_INVALID) {
		if (lock_not_unlock)
			mutex_lock(&pmic_mu);
		else
			mutex_unlock(&pmic_mu);
	}
}

static void stpmic2_lock_access(void)
{
	stpmic2_lock_unlock(true);
}

static void stpmic2_unlock_access(void)
{
	stpmic2_lock_unlock(false);
}

/*
 * Regulator operation handler
 */
static TEE_Result stpmic2_set_state(struct regulator *regulator, bool enable)
{
	struct stpmic2_regu *regu = regulator->priv;
	TEE_Result res = TEE_ERROR_GENERIC;

	FMSG("%s: set state to %u", regulator_name(regulator), enable);

	stpmic2_lock_access();
	res = stpmic2_regulator_set_state(regu->pmic, regu->id, enable);
	stpmic2_unlock_access();

	return res;
}

static TEE_Result stpmic2_get_state(struct regulator *regulator, bool *enabled)
{
	struct stpmic2_regu *regu = regulator->priv;
	TEE_Result res = TEE_ERROR_GENERIC;

	FMSG("%s: get state", regulator_name(regulator));

	stpmic2_lock_access();
	res = stpmic2_regulator_get_state(regu->pmic, regu->id, enabled);
	stpmic2_unlock_access();

	return res;
}

static TEE_Result stpmic2_get_voltage(struct regulator *regulator,
				      int *level_uv)
{
	struct stpmic2_regu *regu = regulator->priv;
	TEE_Result res = TEE_ERROR_GENERIC;
	uint16_t val = 0;

	stpmic2_lock_access();

	if (regu->bypass_uv) {
		uint8_t arg = 0;

		/* If the regul is in bypass mode, return bypass value */
		res = stpmic2_regulator_get_prop(regu->pmic, regu->id,
						 STPMIC2_BYPASS, &arg);
		if (res)
			goto out;

		if (arg == PROP_BYPASS_SET) {
			*level_uv = regu->bypass_uv;
			goto out;
		}
	}

	res = stpmic2_regulator_get_voltage(regu->pmic, regu->id, &val);
	if (res)
		goto out;

	*level_uv = (int)val * 1000;

	FMSG("%s: get voltage: %d uV", regulator_name(regulator), *level_uv);
out:
	stpmic2_unlock_access();

	return res;
}

static TEE_Result stpmic2_set_voltage(struct regulator *regulator, int level_uv)
{
	struct stpmic2_regu *regu = regulator->priv;
	TEE_Result res = TEE_ERROR_GENERIC;

	FMSG("%s: set volt to %d mV", regulator_name(regulator), level_uv);

	stpmic2_lock_access();

	if (level_uv == regu->bypass_uv) {
		res = stpmic2_regulator_set_prop(regu->pmic, regu->id,
						 STPMIC2_BYPASS,
						 PROP_BYPASS_SET);
		/* Do not set voltage in the register */
		goto out;
	}

	res = stpmic2_regulator_set_voltage(regu->pmic, regu->id,
					    level_uv / 1000);
	if (res)
		goto out;

	/* disable bypass after set voltage ; wait settling time ? */
	if (regu->bypass_uv && level_uv != regu->bypass_uv)
		res = stpmic2_regulator_set_prop(regu->pmic, regu->id,
						 STPMIC2_BYPASS,
						 PROP_BYPASS_RESET);
out:
	stpmic2_unlock_access();

	return res;
}

static size_t stpmic2_refine_levels_array(size_t count, int *levels_uv,
					  int min_uv, int max_uv)
{
	size_t n = 0;
	size_t m = 0;

	qsort_int(levels_uv, count);

	/* Remove duplicates and return optimized count */
	for (n = 1; n < count; n++) {
		if (levels_uv[m] != levels_uv[n]) {
			if (m + 1 != n)
				levels_uv[m + 1] = levels_uv[n];
			m++;
		}
	}
	count = m + 1;

	/* Find max voltage index */
	for (n = count; n; n--)
		if (levels_uv[n - 1] <= max_uv)
			break;
	count = n;

	for (n = 0; n < count; n++)
		if (levels_uv[n] >= min_uv)
			break;
	count -= n;

	memmove(levels_uv, levels_uv + n, count * sizeof(*levels_uv));

	return count;
}

static TEE_Result
stpmic2_list_voltages(struct regulator *regulator,
		      struct regulator_voltages_desc **out_desc,
		      const int **out_levels)
{
	struct stpmic2_regu *regu = regulator->priv;

	FMSG("%s: list volt", regulator_name(regulator));

	if (!regu->levels) {
		TEE_Result res = TEE_ERROR_GENERIC;
		const uint16_t *level_ref = NULL;
		size_t level_count = 0;
		size_t count_ref = 0;
		int *levels2 = NULL;
		int *levels = NULL;
		size_t n = 0;

		/*
		 * Allocate and build a consise and ordered voltage list
		 * based on the voltage list provided by stpmic2 driver.
		 * Also add bypass voltage to the list.
		 */
		res = stpmic2_regulator_levels_mv(regu->pmic, regu->id,
						  &level_ref, &count_ref);
		if (res)
			return res;

		if (regu->bypass_uv)
			level_count = count_ref + 1;
		else
			level_count = count_ref;

		levels = calloc(level_count, sizeof(*levels));
		if (!levels)
			return TEE_ERROR_OUT_OF_MEMORY;

		for (n = 0; n < count_ref; n++)
			levels[n] = level_ref[n] * 1000;

		if (regu->bypass_uv)
			levels[n] = regu->bypass_uv;

		level_count = stpmic2_refine_levels_array(level_count, levels,
							  regulator->min_uv,
							  regulator->max_uv);

		/* Shrink levels array to not waste heap memory */
		levels2 = realloc(levels, sizeof(*levels) * level_count);
		if (!levels2) {
			free(levels);
			return TEE_ERROR_OUT_OF_MEMORY;
		}

		regu->levels_desc.type = VOLTAGE_TYPE_FULL_LIST;
		regu->levels_desc.num_levels = level_count;
		regu->levels = levels2;
	}

	*out_desc = &regu->levels_desc;
	*out_levels = regu->levels;

	return TEE_SUCCESS;
}

TEE_Result stpmic2_apply_pm_state(struct regulator *regulator, uint8_t mode)
{
	struct stpmic2_regu *regu = regulator->priv;
	uint8_t state = regu->lp_state[mode];
	int lp_level_uv = regu->lp_level_uv[mode];
	TEE_Result res = TEE_ERROR_GENERIC;

	FMSG("%s: suspend state:%#"PRIx8" %d uV",
	     regulator_name(regulator), state, lp_level_uv);

	if (mode == regu->last_lp_mode)
		return TEE_SUCCESS;

	if (state & STPMIC2_LP_STATE_OFF) {
		res = stpmic2_lp_set_state(regu->pmic, regu->id, false);
		if (res)
			return res;
	}

	if (state & STPMIC2_LP_STATE_ON) {
		res = stpmic2_lp_set_state(regu->pmic, regu->id, true);
		if (res)
			return res;

		if (state & STPMIC2_LP_STATE_SET_VOLT &&
		    regulator->ops->set_voltage)  {
			res = stpmic2_lp_set_voltage(regu->pmic, regu->id,
						     lp_level_uv / 1000);
			if (res)
				return res;
		}
	}

	regu->last_lp_mode = mode;

	return TEE_SUCCESS;
}

TEE_Result stpmic2_suspend_regulator(struct regulator *regulator, uint8_t mode)
{
	struct stpmic2_regu *regu = regulator->priv;
	uint8_t state = regu->lp_state[mode];
	TEE_Result res = TEE_ERROR_GENERIC;
	bool enabled = false;

	/*
	 * If the LP state is controlled by the consumer (power control line
	 * disabled), and the suspend state was requested as OFF in device tree,
	 * then disable the regulator and put a message.
	 */
	if (!regu->power_control_en && (state & STPMIC2_LP_STATE_OFF)) {
		res = stpmic2_regulator_get_state(regu->pmic, regu->id,
						  &enabled);
		if (res)
			return res;

		if (enabled) {
			res = stpmic2_regulator_set_state(regu->pmic, regu->id,
							  false);
			if (res)
				return res;

			IMSG("regulator %s forced OFF",
			     regulator_name(regulator));

			regu->forced_off = true;
		} else {
			regu->forced_off = false;
		}
	}

	return TEE_SUCCESS;
}

TEE_Result stpmic2_resume_regulator(struct regulator *regulator)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct stpmic2_regu *regu = regulator->priv;

	if (regu->forced_off) {
		/* Re-enable a regulator that was forced off in suspend */
		res = stpmic2_regulator_set_state(regu->pmic, regu->id, true);
		if (res)
			return res;

		regu->forced_off = false;
	}

	return TEE_SUCCESS;
}

static TEE_Result stpmic2_init(struct regulator *regulator)
{
	/* default configuration for STPMIC regulator */
	regulator->ramp_delay_uv_per_us = U(2200);
	regulator->enable_ramp_delay_us = U(1000);

	return TEE_SUCCESS;
}

static TEE_Result stpmic2_supplied_init(struct regulator *regulator,
					const void *fdt, int node)
{
	struct stpmic2_regu *regu = regulator->priv;
	const struct stpmic2_regu_dt_property *p = NULL;
	TEE_Result res = TEE_ERROR_GENERIC;

	if (regulator->flags & REGULATOR_PULL_DOWN) {
		res = stpmic2_regulator_set_prop(regu->pmic, regu->id,
						 STPMIC2_PULL_DOWN, 0);
		if (res)
			return res;
	}

	if (regulator->flags & REGULATOR_OVER_CURRENT) {
		res = stpmic2_regulator_set_prop(regu->pmic, regu->id,
						 STPMIC2_OCP, 0);
		if (res)
			return res;
	}

	for (p = prop_table; p < (prop_table + ARRAY_SIZE(prop_table)); p++) {
		const fdt32_t *cuint = NULL;
		uint32_t value = 0;

		cuint = fdt_getprop(fdt, node, p->name, NULL);
		if (!cuint)
			continue;

		if (p->prop == STPMIC2_PWRCTRL_EN)
			regu->power_control_en = true;

		value = fdt32_to_cpu(*cuint);
		FMSG("%s: %d, %#"PRIx32, regulator_name(regulator), p->prop,
		     value);

		res = stpmic2_regulator_set_prop(regu->pmic, regu->id,
						 p->prop, value);
		if (res)
			return res;
	}

	res = plat_stpmic2_supplied_init(regulator);
	if (res) {
		free(regu);
		return res;
	}

	return TEE_SUCCESS;
}

const struct regulator_ops stpmic2_regu_ops = {
	.set_state = stpmic2_set_state,
	.get_state = stpmic2_get_state,
	.set_voltage = stpmic2_set_voltage,
	.get_voltage = stpmic2_get_voltage,
	.supported_voltages = stpmic2_list_voltages,
	.init = stpmic2_init,
	.supplied_init = stpmic2_supplied_init,
};

const struct regulator_ops stpmic2_switch_ops = {
	.set_state = stpmic2_set_state,
	.get_state = stpmic2_get_state,
	.init = stpmic2_init,
	.supplied_init = stpmic2_supplied_init,
};

static void stpmic2_parse_regu_node(struct regu_dt_desc *regu_desc,
				    const void *fdt, int node)
{
	struct stpmic2_regu *regu = regu_desc->priv;
	const fdt32_t *cuint = NULL;
	const char __maybe_unused *regu_name = regu_desc->name;

	cuint = fdt_getprop(fdt, node, "st,regulator-bypass-microvolt", NULL);
	if (!cuint)
		return;

	regu->bypass_uv = fdt32_to_cpu(*cuint);
	FMSG("%s: bypass= %#"PRIx32"uV", regu_name, regu->bypass_uv);
}

static void stpmic2_parse_low_power_mode(const void *fdt, int node,
					 struct regu_dt_desc *regu_desc,
					 int mode)
{
	struct stpmic2_regu *regu = regu_desc->priv;
	const fdt32_t *cuint = NULL;
	const char __maybe_unused *regu_name = regu_desc->name;

	regu->last_lp_mode = STPMIC2_LP_STATE_INVALID;
	regu->lp_state[mode] = 0;

	if (fdt_getprop(fdt, node, "regulator-off-in-suspend", NULL)) {
		FMSG("%s: mode:%d OFF", regu_name, mode);
		regu->lp_state[mode] |= STPMIC2_LP_STATE_OFF;
	} else if (fdt_getprop(fdt, node, "regulator-on-in-suspend", NULL)) {
		FMSG("%s: mode:%d ON", regu_name, mode);
		regu->lp_state[mode] |= STPMIC2_LP_STATE_ON;
	} else {
		regu->lp_state[mode] |= STPMIC2_LP_STATE_UNMODIFIED;
	}

	cuint = fdt_getprop(fdt, node, "regulator-suspend-microvolt", NULL);
	if (cuint) {
		int level_uv = (int)fdt32_to_cpu(*cuint);

		FMSG("%s: mode:%d suspend to %d uV", regu_name, mode, level_uv);

		regu->lp_state[mode] |= STPMIC2_LP_STATE_SET_VOLT;
		regu->lp_level_uv[mode] = level_uv;
	}
}

static void stpmic2_parse_low_power_modes(const void *fdt, int node,
					  struct regu_dt_desc *regu_desc)
{
	unsigned int mode = 0;

	for (mode = 0; mode < plat_stpmic2_get_lp_mode_count(); mode++) {
		const char *lp_mode_name = plat_stpmic2_get_lp_mode_name(mode);

		if (lp_mode_name) {
			int n = 0;

			/* Get the configs from regulator_state_node subnode */
			n = fdt_subnode_offset(fdt, node, lp_mode_name);
			if (n >= 0)
				stpmic2_parse_low_power_mode(fdt, n, regu_desc,
							     mode);
		}
	}
}

static TEE_Result stpmic2_register_regulator(const void *fdt,
					     struct stpmic2 *pmic,
					     const char *regu_name, int node,
					     int parent_node)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	const struct stpmic2_compat_data *cdata = pmic->compat_data;
	struct regu_dt_desc desc = { };
	struct stpmic2_regu *regu = NULL;
	uint32_t index = 0;
	uint8_t id = 0;
	const char *desc_name = regu_name;

	FMSG("Stpmic2 register %s", desc_name);

	/* In case of STPMIC1L or STPMIC2L */
	if (!strcmp(desc_name, "buck1")) {
		bool high = false;

		res = stpmic2_is_buck1_high_voltage(pmic, &high);
		if (res) {
			EMSG("Failed to get %s id", desc_name);
			return res;
		}

		if (high) {
			FMSG("Buck1 in high voltage range");
			desc_name = "buck1h";
		}
	}

	/* Find the regulator platform description */
	for (index = 0; index < cdata->desc_len; index++)
		if (!strcmp(cdata->desc_table[index].name, desc_name))
			break;
	assert(index < cdata->desc_len);

	desc = cdata->desc_table[index];

	/* Find the regulator id */
	res = stpmic2_regulator_get_id(desc_name, &id);
	if (res) {
		EMSG("Failed to get %s id", desc_name);
		return res;
	}

	regu = calloc(1, sizeof(*regu));
	if (!regu)
		return TEE_ERROR_OUT_OF_MEMORY;

	regu->pmic = pmic;
	regu->id = id;

	regu->lp_state = calloc(plat_stpmic2_get_lp_mode_count(),
				sizeof(*regu));
	if (!regu->lp_state) {
		free(regu);
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	regu->lp_level_uv = calloc(plat_stpmic2_get_lp_mode_count(),
				   sizeof(*regu));
	if (!regu->lp_level_uv) {
		free(regu->lp_state);
		free(regu);
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	desc.priv = regu;

	stpmic2_parse_regu_node(&desc, fdt, node);

	stpmic2_parse_low_power_modes(fdt, node, &desc);

	res = regulator_dt_register(fdt, node, parent_node, &desc);
	if (res) {
		EMSG("Failed to register %s", regu_name);
		free(regu->lp_level_uv);
		free(regu->lp_state);
		free(regu);
		return res;
	}

	return TEE_SUCCESS;
}

static TEE_Result stpmic2_parse_regulator_fdt_nodes(const void *fdt, int node,
						    struct stpmic2 *pmic)
{
	int regulators_node = 0;
	int regu_node = 0;

	regulators_node = fdt_subnode_offset(fdt, node, "regulators");
	if (regulators_node < 0)
		panic();

	fdt_for_each_subnode(regu_node, fdt, regulators_node) {
		TEE_Result res = TEE_ERROR_GENERIC;
		int status = fdt_get_status(fdt, regu_node);
		const char *regu_name = NULL;

		assert(status >= 0);
		if (status == DT_STATUS_DISABLED)
			continue;

		regu_name = fdt_get_name(fdt, regu_node, NULL);
		assert(regu_name);

		res = stpmic2_register_regulator(fdt, pmic, regu_name,
						 regu_node, regulators_node);
		if (res) {
			EMSG("Failed to register %s", regu_name);
			return res;
		}
	}

	return TEE_SUCCESS;
}

static TEE_Result stpmic2_pm(enum pm_op op, uint32_t pm_hint,
			     const struct pm_callback_handle *pm_handle)
{
	struct stpmic2 *pmic = pm_handle->handle;
	unsigned int pwrlvl = PM_HINT_PLATFORM_STATE(pm_hint);
	TEE_Result res = TEE_SUCCESS;

	if (op == PM_OP_SUSPEND) {
		if (pwrlvl == STM32_PM_SWITCH_OFF &&
		    pmic->system_power_controller) {
			IMSG("PMIC STPMIC2 software power off");
			console_flush();
			mdelay(10);
			res = stpmic2_switch_off(pmic);
			udelay(100);
		}
	}

	return res;
}

static void stpmic2_initialize_i2c(const void *fdt, int node,
				   struct stpmic2 *pmic,
				   struct i2c_handle_s *i2c)
{
	const fdt32_t *cuint = NULL;
	uint32_t i2c_addr = 0;

	cuint = fdt_getprop(fdt, node, "reg", NULL);
	if (!cuint)
		panic("STPMIC2 configuration failed on reg property");

	i2c_addr = fdt32_to_cpu(*cuint) << 1;
	if (i2c_addr > UINT16_MAX)
		panic("STPMIC2 configuration failed on i2c address translation");

	if (!stm32_i2c_is_device_ready(i2c, i2c_addr, PMIC_I2C_TRIALS,
				       PMIC_I2C_TIMEOUT_BUSY_MS))
		panic("STPMIC2 I2C init failed");

	pmic->i2c_handle = i2c;
	pmic->i2c_addr = i2c_addr;
}

/*
 * STPMIC and resource initialization
 */
static void stpmic2_initialize(const void *fdt, int node,
			       struct stpmic2 *pmic, struct i2c_handle_s *i2c)
{
	const struct stpmic2_compat_data __maybe_unused *cdata =
		pmic->compat_data;
	uint8_t ver = 0;
	uint8_t pid = 0;

	FMSG("Initialize stpmic2");

	stpmic2_initialize_i2c(fdt, node, pmic, i2c);

	if (stpmic2_get_product_id(pmic, &pid) ||
	    stpmic2_get_version(pmic, &ver))
		panic("Failed to access PMIC");

	pmic->ref_id = ((pid & PMIC_REF_ID_MASK) >> PMIC_REF_ID_SHIFT);

	/* NVM version A stands for NVM_ID=1 */
	IMSG("PMIC STPMIC REFID:%"PRIu8".%c V%"PRIu8".%"PRIu8,
	     pmic->ref_id,
	     'A' + (pid & PMIC_NVM_ID_MASK) - U(1),
	     (ver & MAJOR_VERSION_MASK) >> MAJOR_VERSION_SHIFT,
	     ver & MINOR_VERSION_MASK);

	assert(pmic->ref_id == cdata->ref_id);

	stpmic2_dump_regulators(pmic);
}

static TEE_Result stpmic2_probe(const void *fdt, int node,
				const void *compat_data)
{
	struct stm32_i2c_dev *stm32_i2c_dev = NULL;
	struct i2c_dev *i2c_dev = NULL;
	struct stpmic2 *pmic = NULL;
	TEE_Result res = TEE_SUCCESS;

	FMSG("Probe stpmic2");

	res = i2c_dt_get_dev(fdt, node, &i2c_dev);
	if (res)
		return res;

	stm32_i2c_dev = container_of(i2c_dev, struct stm32_i2c_dev, i2c_dev);

	pmic = calloc(1, sizeof(*pmic));
	if (!pmic)
		panic();

	pmic->compat_data = compat_data;
	pmic->system_power_controller = dt_have_prop(fdt, node,
						     "system-power-controller");

	stpmic2_initialize(fdt, node, pmic, stm32_i2c_dev->handle);

	res = stpmic2_parse_regulator_fdt_nodes(fdt, node, pmic);
	if (res)
		panic();

	register_pm_core_service_cb(stpmic2_pm, pmic, "stpmic2");

	return TEE_SUCCESS;
}

#define DEFINE_REGU(_name) { \
		.name = (_name), \
		.ops = &stpmic2_regu_ops, \
	}

#define DEFINE_SWITCH(_name) { \
		.name = (_name), \
		.ops = &stpmic2_switch_ops, \
	}

const struct regu_dt_desc stpmic25_reguls[] = {
	DEFINE_REGU("buck1"),
	DEFINE_REGU("buck2"),
	DEFINE_REGU("buck3"),
	DEFINE_REGU("buck4"),
	DEFINE_REGU("buck5"),
	DEFINE_REGU("buck6"),
	DEFINE_REGU("buck7"),
	DEFINE_REGU("ldo1"),
	DEFINE_REGU("ldo2"),
	DEFINE_REGU("ldo3"),
	DEFINE_REGU("ldo4"),
	DEFINE_REGU("ldo5"),
	DEFINE_REGU("ldo6"),
	DEFINE_REGU("ldo7"),
	DEFINE_REGU("ldo8"),
	DEFINE_SWITCH("refddr"),
};
DECLARE_KEEP_PAGER(stpmic25_reguls);

const struct regu_dt_desc stpmic1l_reguls[] = {
	DEFINE_REGU("buck1"),
	DEFINE_REGU("buck1h"),
	DEFINE_REGU("buck2"),
	DEFINE_REGU("ldo2"),
	DEFINE_REGU("ldo3"),
	DEFINE_REGU("ldo4"),
	DEFINE_REGU("ldo5"),
	DEFINE_SWITCH("gpo1"),
	DEFINE_SWITCH("gpo2"),
};
DECLARE_KEEP_PAGER(stpmic1l_reguls);

const struct regu_dt_desc stpmic2l_reguls[] = {
	DEFINE_REGU("buck1"),
	DEFINE_REGU("buck1h"),
	DEFINE_REGU("buck2"),
	DEFINE_REGU("buck3"),
	DEFINE_REGU("ldo1"),
	DEFINE_REGU("ldo2"),
	DEFINE_REGU("ldo3"),
	DEFINE_REGU("ldo4"),
	DEFINE_REGU("ldo5"),
	DEFINE_REGU("ldo6"),
	DEFINE_REGU("ldo7"),
	DEFINE_SWITCH("gpo1"),
	DEFINE_SWITCH("gpo2"),
	DEFINE_SWITCH("gpo3"),
	DEFINE_SWITCH("gpo4"),
	DEFINE_SWITCH("gpo5"),
};
DECLARE_KEEP_PAGER(stpmic2l_reguls);

static const struct stpmic2_compat_data stpmic25_cdata = {
	.desc_table = stpmic25_reguls,
	.desc_len = ARRAY_SIZE(stpmic25_reguls),
	.ref_id =  PMIC_REF_ID_STPMIC25,
};

static const struct stpmic2_compat_data stpmic1l_cdata = {
	.desc_table = stpmic1l_reguls,
	.desc_len = ARRAY_SIZE(stpmic1l_reguls),
	.ref_id =  PMIC_REF_ID_STPMIC1L,
};

static const struct stpmic2_compat_data stpmic2l_cdata = {
	.desc_table = stpmic2l_reguls,
	.desc_len = ARRAY_SIZE(stpmic2l_reguls),
	.ref_id =  PMIC_REF_ID_STPMIC2L,
};

static const struct dt_device_match stpmic2_match_table[] = {
	{
		.compatible = "st,stpmic2",
		.compat_data = &stpmic25_cdata,
	},
	{
		.compatible = "st,stpmic1l",
		.compat_data = &stpmic1l_cdata,
	},
	{
		.compatible = "st,stpmic2l",
		.compat_data = &stpmic2l_cdata,
	},
	{ }
};

DEFINE_DT_DRIVER(stpmic2_dt_driver) = {
	.name = "stpmic2",
	.match_table = stpmic2_match_table,
	.probe = stpmic2_probe,
};
