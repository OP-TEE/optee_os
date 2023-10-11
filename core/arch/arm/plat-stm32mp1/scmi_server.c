// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2019-2022, STMicroelectronics
 */
#include <assert.h>
#include <compiler.h>
#include <confine_array_index.h>
#include <drivers/clk.h>
#include <drivers/clk_dt.h>
#include <drivers/regulator.h>
#include <drivers/rstctrl.h>
#include <drivers/scmi-msg.h>
#include <drivers/scmi.h>
#include <drivers/stm32_vrefbuf.h>
#include <drivers/stm32mp1_pmic.h>
#include <drivers/stm32mp1_pwr.h>
#include <drivers/stpmic1.h>
#include <drivers/stpmic1_regulator.h>
#include <drivers/stm32mp_dt_bindings.h>
#include <initcall.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <platform_config.h>
#include <stdint.h>
#include <speculation_barrier.h>
#include <stm32_util.h>
#include <string.h>
#include <tee_api_defines.h>
#include <util.h>

#define TIMEOUT_US_1MS		1000

#define SCMI_CLOCK_NAME_SIZE	16
#define SCMI_RD_NAME_SIZE	16
#define SCMI_VOLTD_NAME_SIZE	16

/*
 * struct stm32_scmi_clk - Data for the exposed clock
 * @clock_id: Clock identifier in RCC clock driver
 * @name: Clock string ID exposed to channel
 * @enabled: State of the SCMI clock
 */
struct stm32_scmi_clk {
	unsigned long clock_id;
	struct clk *clk;
	const char *name;
	bool enabled;
};

/*
 * struct stm32_scmi_rd - Data for the exposed reset controller
 * @reset_id: Reset identifier in RCC reset driver
 * @name: Reset string ID exposed to channel
 * @rstctrl: Reset controller device
 */
struct stm32_scmi_rd {
	unsigned long reset_id;
	const char *name;
	struct rstctrl *rstctrl;
};

enum voltd_device {
	VOLTD_PWR,
	VOLTD_PMIC,
	VOLTD_VREFBUF,
	/* Stub regulator until regulator framework is merged */
	VOLTD_STUB,
};

/*
 * struct stm32_scmi_voltd - Data for the exposed voltage domains
 * @name: Power regulator string ID exposed to channel
 * @priv_id: Internal string ID for the regulator
 * @priv_dev: Internal ID for the device implementing the regulator
 * @regulator: Regulator controller device
 * @state: State of the SCMI voltage domain (true: enable, false: disable)
 */
struct stm32_scmi_voltd {
	const char *name;
	const char *priv_id;
	enum voltd_device priv_dev;
	struct regulator *regulator;
	bool state;
};

#if CFG_STM32MP1_SCMI_SHM_BASE
register_phys_mem(MEM_AREA_IO_NSEC, CFG_STM32MP1_SCMI_SHM_BASE,
		  CFG_STM32MP1_SCMI_SHM_SIZE);

/* Locate all non-secure SMT message buffers in last page of SYSRAM */
#define SMT_BUFFER_BASE		CFG_STM32MP1_SCMI_SHM_BASE

#if (SMT_BUFFER_BASE + SMT_BUF_SLOT_SIZE > \
	CFG_STM32MP1_SCMI_SHM_BASE + CFG_STM32MP1_SCMI_SHM_SIZE)
#error "SCMI shared memory mismatch"
#endif
#endif /*CFG_STM32MP1_SCMI_SHM_BASE*/

#define CLOCK_CELL(_scmi_id, _id, _name, _init_enabled) \
	[(_scmi_id)] = { \
		.clock_id = (_id), \
		.name = (_name), \
		.enabled = (_init_enabled), \
	}

#define RESET_CELL(_scmi_id, _id, _name) \
	[(_scmi_id)] = { \
		.reset_id = (_id), \
		.name = (_name), \
	}

#define VOLTD_CELL(_scmi_id, _dev_id, _priv_id, _name) \
	[(_scmi_id)] = { \
		.priv_id = (_priv_id), \
		.priv_dev = (_dev_id), \
		.name = (_name), \
	}

#ifdef CFG_STM32MP13
static struct stm32_scmi_clk stm32_scmi_clock[] = {
	CLOCK_CELL(CK_SCMI_HSE, CK_HSE, "ck_hse", true),
	CLOCK_CELL(CK_SCMI_HSI, CK_HSI, "ck_hsi", true),
	CLOCK_CELL(CK_SCMI_CSI, CK_CSI, "ck_csi", true),
	CLOCK_CELL(CK_SCMI_LSE, CK_LSE, "ck_lse", true),
	CLOCK_CELL(CK_SCMI_LSI, CK_LSI, "ck_lsi", true),
	CLOCK_CELL(CK_SCMI_HSE_DIV2, CK_HSE_DIV2, "clk-hse-div2", true),
	CLOCK_CELL(CK_SCMI_PLL2_Q, PLL2_Q, "pll2_q", true),
	CLOCK_CELL(CK_SCMI_PLL2_R, PLL2_R, "pll2_r", true),
	CLOCK_CELL(CK_SCMI_PLL3_P, PLL3_P, "pll3_p", true),
	CLOCK_CELL(CK_SCMI_PLL3_Q, PLL3_Q, "pll3_q", true),
	CLOCK_CELL(CK_SCMI_PLL3_R, PLL3_R, "pll3_r", true),
	CLOCK_CELL(CK_SCMI_PLL4_P, PLL4_P, "pll4_p", true),
	CLOCK_CELL(CK_SCMI_PLL4_Q, PLL4_Q, "pll4_q", true),
	CLOCK_CELL(CK_SCMI_PLL4_R, PLL4_R, "pll4_r", true),
	CLOCK_CELL(CK_SCMI_MPU, CK_MPU, "ck_mpu", true),
	CLOCK_CELL(CK_SCMI_AXI, CK_AXI, "ck_axi", true),
	CLOCK_CELL(CK_SCMI_MLAHB, CK_MLAHB, "ck_mlahb", true),
	CLOCK_CELL(CK_SCMI_CKPER, CK_PER, "ck_per", true),
	CLOCK_CELL(CK_SCMI_PCLK1, PCLK1, "pclk1", true),
	CLOCK_CELL(CK_SCMI_PCLK2, PCLK2, "pclk2", true),
	CLOCK_CELL(CK_SCMI_PCLK3, PCLK3, "pclk3", true),
	CLOCK_CELL(CK_SCMI_PCLK4, PCLK4, "pclk4", true),
	CLOCK_CELL(CK_SCMI_PCLK5, PCLK5, "pclk5", true),
	CLOCK_CELL(CK_SCMI_PCLK6, PCLK6, "pclk6", true),
	CLOCK_CELL(CK_SCMI_CKTIMG1, CK_TIMG1, "timg1_ck", true),
	CLOCK_CELL(CK_SCMI_CKTIMG2, CK_TIMG2, "timg2_ck", true),
	CLOCK_CELL(CK_SCMI_CKTIMG3, CK_TIMG3, "timg3_ck", true),
	CLOCK_CELL(CK_SCMI_RTC, RTC, "ck_rtc", true),
	CLOCK_CELL(CK_SCMI_RTCAPB, RTCAPB, "rtcapb", true),
	CLOCK_CELL(CK_SCMI_BSEC, BSEC, "bsec", true),
};
#endif

#ifdef CFG_STM32MP15
static struct stm32_scmi_clk stm32_scmi_clock[] = {
	CLOCK_CELL(CK_SCMI_HSE, CK_HSE, "ck_hse", true),
	CLOCK_CELL(CK_SCMI_HSI, CK_HSI, "ck_hsi", true),
	CLOCK_CELL(CK_SCMI_CSI, CK_CSI, "ck_csi", true),
	CLOCK_CELL(CK_SCMI_LSE, CK_LSE, "ck_lse", true),
	CLOCK_CELL(CK_SCMI_LSI, CK_LSI, "ck_lsi", true),
	CLOCK_CELL(CK_SCMI_PLL2_Q, PLL2_Q, "pll2_q", true),
	CLOCK_CELL(CK_SCMI_PLL2_R, PLL2_R, "pll2_r", true),
	CLOCK_CELL(CK_SCMI_MPU, CK_MPU, "ck_mpu", true),
	CLOCK_CELL(CK_SCMI_AXI, CK_AXI, "ck_axi", true),
	CLOCK_CELL(CK_SCMI_BSEC, BSEC, "bsec", true),
	CLOCK_CELL(CK_SCMI_CRYP1, CRYP1, "cryp1", false),
	CLOCK_CELL(CK_SCMI_GPIOZ, GPIOZ, "gpioz", false),
	CLOCK_CELL(CK_SCMI_HASH1, HASH1, "hash1", false),
	CLOCK_CELL(CK_SCMI_I2C4, I2C4_K, "i2c4_k", false),
	CLOCK_CELL(CK_SCMI_I2C6, I2C6_K, "i2c6_k", false),
	CLOCK_CELL(CK_SCMI_IWDG1, IWDG1, "iwdg1", false),
	CLOCK_CELL(CK_SCMI_RNG1, RNG1_K, "rng1_k", true),
	CLOCK_CELL(CK_SCMI_RTC, RTC, "ck_rtc", true),
	CLOCK_CELL(CK_SCMI_RTCAPB, RTCAPB, "rtcapb", true),
	CLOCK_CELL(CK_SCMI_SPI6, SPI6_K, "spi6_k", false),
	CLOCK_CELL(CK_SCMI_USART1, USART1_K, "usart1_k", false),
};
#endif

#ifdef CFG_STM32MP13
static struct stm32_scmi_rd stm32_scmi_reset_domain[] = {
	RESET_CELL(RST_SCMI_LTDC, LTDC_R, "ltdc"),
	RESET_CELL(RST_SCMI_MDMA, MDMA_R, "mdma"),
};
#endif

#ifdef CFG_STM32MP15
static struct stm32_scmi_rd stm32_scmi_reset_domain[] = {
	RESET_CELL(RST_SCMI_SPI6, SPI6_R, "spi6"),
	RESET_CELL(RST_SCMI_I2C4, I2C4_R, "i2c4"),
	RESET_CELL(RST_SCMI_I2C6, I2C6_R, "i2c6"),
	RESET_CELL(RST_SCMI_USART1, USART1_R, "usart1"),
	RESET_CELL(RST_SCMI_STGEN, STGEN_R, "stgen"),
	RESET_CELL(RST_SCMI_GPIOZ, GPIOZ_R, "gpioz"),
	RESET_CELL(RST_SCMI_CRYP1, CRYP1_R, "cryp1"),
	RESET_CELL(RST_SCMI_HASH1, HASH1_R, "hash1"),
	RESET_CELL(RST_SCMI_RNG1, RNG1_R, "rng1"),
	RESET_CELL(RST_SCMI_MDMA, MDMA_R, "mdma"),
	RESET_CELL(RST_SCMI_MCU, MCU_R, "mcu"),
	RESET_CELL(RST_SCMI_MCU_HOLD_BOOT, MCU_HOLD_BOOT_R, "mcu_hold_boot"),
};
#endif

#define PWR_REG11_NAME_ID		"0"
#define PWR_REG18_NAME_ID		"1"
#define PWR_USB33_NAME_ID		"2"

#define STUB_SDMMC1_IO_NAME_ID		"sdmmc1"
#define STUB_SDMMC2_IO_NAME_ID		"sdmmc2"

#ifdef CFG_STM32MP13
struct stm32_scmi_voltd scmi_voltage_domain[] = {
	VOLTD_CELL(VOLTD_SCMI_REG11, VOLTD_PWR, PWR_REG11_NAME_ID, "reg11"),
	VOLTD_CELL(VOLTD_SCMI_REG18, VOLTD_PWR, PWR_REG18_NAME_ID, "reg18"),
	VOLTD_CELL(VOLTD_SCMI_USB33, VOLTD_PWR, PWR_USB33_NAME_ID, "usb33"),
	VOLTD_CELL(VOLTD_SCMI_SDMMC1_IO, VOLTD_STUB, STUB_SDMMC1_IO_NAME_ID,
		   "sdmmc1"),
	VOLTD_CELL(VOLTD_SCMI_SDMMC2_IO, VOLTD_STUB, STUB_SDMMC2_IO_NAME_ID,
		   "sdmmc2"),
	VOLTD_CELL(VOLTD_SCMI_VREFBUF, VOLTD_VREFBUF, "vrefbuf", "vrefbuf"),
	VOLTD_CELL(VOLTD_SCMI_STPMIC1_BUCK1, VOLTD_PMIC, "buck1", "buck1"),
	VOLTD_CELL(VOLTD_SCMI_STPMIC1_BUCK2, VOLTD_PMIC, "buck2", "buck2"),
	VOLTD_CELL(VOLTD_SCMI_STPMIC1_BUCK3, VOLTD_PMIC, "buck3", "buck3"),
	VOLTD_CELL(VOLTD_SCMI_STPMIC1_BUCK4, VOLTD_PMIC, "buck4", "buck4"),
	VOLTD_CELL(VOLTD_SCMI_STPMIC1_LDO1, VOLTD_PMIC, "ldo1", "ldo1"),
	VOLTD_CELL(VOLTD_SCMI_STPMIC1_LDO2, VOLTD_PMIC, "ldo2", "ldo2"),
	VOLTD_CELL(VOLTD_SCMI_STPMIC1_LDO3, VOLTD_PMIC, "ldo3", "ldo3"),
	VOLTD_CELL(VOLTD_SCMI_STPMIC1_LDO4, VOLTD_PMIC, "ldo4", "ldo4"),
	VOLTD_CELL(VOLTD_SCMI_STPMIC1_LDO5, VOLTD_PMIC, "ldo5", "ldo5"),
	VOLTD_CELL(VOLTD_SCMI_STPMIC1_LDO6, VOLTD_PMIC, "ldo6", "ldo6"),
	VOLTD_CELL(VOLTD_SCMI_STPMIC1_VREFDDR, VOLTD_PMIC, "vref_ddr",
		   "vref_ddr"),
	VOLTD_CELL(VOLTD_SCMI_STPMIC1_BOOST, VOLTD_PMIC, "boost", "bst_out"),
	VOLTD_CELL(VOLTD_SCMI_STPMIC1_PWR_SW1, VOLTD_PMIC, "pwr_sw1",
		   "pwr_sw1"),
	VOLTD_CELL(VOLTD_SCMI_STPMIC1_PWR_SW2, VOLTD_PMIC, "pwr_sw2",
		   "pwr_sw2"),
};
#endif

#ifdef CFG_STM32MP15
struct stm32_scmi_voltd scmi_voltage_domain[] = {
	VOLTD_CELL(VOLTD_SCMI_REG11, VOLTD_PWR, PWR_REG11_NAME_ID, "reg11"),
	VOLTD_CELL(VOLTD_SCMI_REG18, VOLTD_PWR, PWR_REG18_NAME_ID, "reg18"),
	VOLTD_CELL(VOLTD_SCMI_USB33, VOLTD_PWR, PWR_USB33_NAME_ID, "usb33"),
	VOLTD_CELL(VOLTD_SCMI_STPMIC1_BUCK1, VOLTD_PMIC, "buck1", "vddcore"),
	VOLTD_CELL(VOLTD_SCMI_STPMIC1_BUCK2, VOLTD_PMIC, "buck2", "vdd_ddr"),
	VOLTD_CELL(VOLTD_SCMI_STPMIC1_BUCK3, VOLTD_PMIC, "buck3", "vdd"),
	VOLTD_CELL(VOLTD_SCMI_STPMIC1_BUCK4, VOLTD_PMIC, "buck4", "v3v3"),
	VOLTD_CELL(VOLTD_SCMI_STPMIC1_LDO1, VOLTD_PMIC, "ldo1", "v1v8_audio"),
	VOLTD_CELL(VOLTD_SCMI_STPMIC1_LDO2, VOLTD_PMIC, "ldo2", "v3v3_hdmi"),
	VOLTD_CELL(VOLTD_SCMI_STPMIC1_LDO3, VOLTD_PMIC, "ldo3", "vtt_ddr"),
	VOLTD_CELL(VOLTD_SCMI_STPMIC1_LDO4, VOLTD_PMIC, "ldo4", "vdd_usb"),
	VOLTD_CELL(VOLTD_SCMI_STPMIC1_LDO5, VOLTD_PMIC, "ldo5", "vdda"),
	VOLTD_CELL(VOLTD_SCMI_STPMIC1_LDO6, VOLTD_PMIC, "ldo6", "v1v2_hdmi"),
	VOLTD_CELL(VOLTD_SCMI_STPMIC1_VREFDDR, VOLTD_PMIC, "vref_ddr",
		   "vref_ddr"),
	VOLTD_CELL(VOLTD_SCMI_STPMIC1_BOOST, VOLTD_PMIC, "boost", "bst_out"),
	VOLTD_CELL(VOLTD_SCMI_STPMIC1_PWR_SW1, VOLTD_PMIC, "pwr_sw1",
		   "vbus_otg"),
	VOLTD_CELL(VOLTD_SCMI_STPMIC1_PWR_SW2, VOLTD_PMIC, "pwr_sw2",
		   "vbus_sw"),
};
#endif

struct channel_resources {
	struct scmi_msg_channel *channel;
	struct stm32_scmi_clk *clock;
	size_t clock_count;
	struct stm32_scmi_rd *rd;
	size_t rd_count;
	struct stm32_scmi_voltd *voltd;
	size_t voltd_count;
};

static const struct channel_resources scmi_channel[] = {
	[0] = {
		.channel = &(struct scmi_msg_channel){
#ifdef SMT_BUFFER_BASE
			.shm_addr = { .pa = SMT_BUFFER_BASE },
			.shm_size = SMT_BUF_SLOT_SIZE,
#endif
		},
		.clock = stm32_scmi_clock,
		.clock_count = ARRAY_SIZE(stm32_scmi_clock),
		.rd = stm32_scmi_reset_domain,
		.rd_count = ARRAY_SIZE(stm32_scmi_reset_domain),
		.voltd = scmi_voltage_domain,
		.voltd_count = ARRAY_SIZE(scmi_voltage_domain),
	},
};

static const struct channel_resources *find_resource(unsigned int channel_id)
{
	assert(channel_id < ARRAY_SIZE(scmi_channel));

	return scmi_channel + channel_id;
}

struct scmi_msg_channel *plat_scmi_get_channel(unsigned int channel_id)
{
	const size_t max_id = ARRAY_SIZE(scmi_channel);
	unsigned int confined_id = confine_array_index(channel_id, max_id);

	if (channel_id >= max_id)
		return NULL;

	return find_resource(confined_id)->channel;
}

static size_t __maybe_unused plat_scmi_protocol_count_paranoid(void)
{
	unsigned int n = 0;
	unsigned int count = 0;
	const size_t channel_count = ARRAY_SIZE(scmi_channel);

	for (n = 0; n < channel_count; n++)
		if (scmi_channel[n].clock_count)
			break;
	if (n < channel_count)
		count++;

	for (n = 0; n < channel_count; n++)
		if (scmi_channel[n].rd_count)
			break;
	if (n < channel_count)
		count++;

	for (n = 0; n < channel_count; n++)
		if (scmi_channel[n].voltd_count)
			break;
	if (n < channel_count)
		count++;

	return count;
}

static const char vendor[] = "ST";
static const char sub_vendor[] = "";

const char *plat_scmi_vendor_name(void)
{
	return vendor;
}

const char *plat_scmi_sub_vendor_name(void)
{
	return sub_vendor;
}

/* Currently supporting Clocks and Reset Domains */
static const uint8_t plat_protocol_list[] = {
	SCMI_PROTOCOL_ID_CLOCK,
	SCMI_PROTOCOL_ID_RESET_DOMAIN,
	SCMI_PROTOCOL_ID_VOLTAGE_DOMAIN,
	0 /* Null termination */
};

size_t plat_scmi_protocol_count(void)
{
	const size_t count = ARRAY_SIZE(plat_protocol_list) - 1;

	assert(count == plat_scmi_protocol_count_paranoid());

	return count;
}

const uint8_t *plat_scmi_protocol_list(unsigned int channel_id __unused)
{
	assert(plat_scmi_protocol_count_paranoid() ==
	       (ARRAY_SIZE(plat_protocol_list) - 1));

	return plat_protocol_list;
}

/*
 * Platform SCMI clocks
 */
static struct stm32_scmi_clk *find_clock(unsigned int channel_id,
					 unsigned int scmi_id)
{
	const struct channel_resources *resource = find_resource(channel_id);
	size_t n = 0;

	if (resource) {
		for (n = 0; n < resource->clock_count; n++)
			if (n == scmi_id)
				return &resource->clock[n];
	}

	return NULL;
}

size_t plat_scmi_clock_count(unsigned int channel_id)
{
	const struct channel_resources *resource = find_resource(channel_id);

	if (!resource)
		return 0;

	return resource->clock_count;
}

const char *plat_scmi_clock_get_name(unsigned int channel_id,
				     unsigned int scmi_id)
{
	struct stm32_scmi_clk *clock = find_clock(channel_id, scmi_id);

	if (!clock || !stm32mp_nsec_can_access_clock(clock->clock_id))
		return NULL;

	return clock->name;
}

int32_t plat_scmi_clock_rates_array(unsigned int channel_id,
				    unsigned int scmi_id, size_t start_index,
				    unsigned long *array, size_t *nb_elts)
{
	struct stm32_scmi_clk *clock = find_clock(channel_id, scmi_id);

	if (!clock)
		return SCMI_NOT_FOUND;

	if (!stm32mp_nsec_can_access_clock(clock->clock_id))
		return SCMI_DENIED;

	/* Exposed clocks are currently fixed rate clocks */
	if (start_index)
		return SCMI_INVALID_PARAMETERS;

	if (!array)
		*nb_elts = 1;
	else if (*nb_elts == 1)
		*array = clk_get_rate(clock->clk);
	else
		return SCMI_GENERIC_ERROR;

	return SCMI_SUCCESS;
}

unsigned long plat_scmi_clock_get_rate(unsigned int channel_id,
				       unsigned int scmi_id)
{
	struct stm32_scmi_clk *clock = find_clock(channel_id, scmi_id);

	if (!clock || !stm32mp_nsec_can_access_clock(clock->clock_id))
		return 0;

	return clk_get_rate(clock->clk);
}

int32_t plat_scmi_clock_get_state(unsigned int channel_id, unsigned int scmi_id)
{
	struct stm32_scmi_clk *clock = find_clock(channel_id, scmi_id);

	if (!clock || !stm32mp_nsec_can_access_clock(clock->clock_id))
		return 0;

	return (int32_t)clock->enabled;
}

int32_t plat_scmi_clock_set_state(unsigned int channel_id, unsigned int scmi_id,
				  bool enable_not_disable)
{
	struct stm32_scmi_clk *clock = find_clock(channel_id, scmi_id);

	if (!clock)
		return SCMI_NOT_FOUND;

	if (!stm32mp_nsec_can_access_clock(clock->clock_id))
		return SCMI_DENIED;

	if (enable_not_disable) {
		if (!clock->enabled) {
			FMSG("SCMI clock %u enable", scmi_id);
			clk_enable(clock->clk);
			clock->enabled = true;
		}
	} else {
		if (clock->enabled) {
			FMSG("SCMI clock %u disable", scmi_id);
			clk_disable(clock->clk);
			clock->enabled = false;
		}
	}

	return SCMI_SUCCESS;
}

/*
 * Platform SCMI reset domains
 */
static struct stm32_scmi_rd *find_rd(unsigned int channel_id,
				     unsigned int scmi_id)
{
	const struct channel_resources *resource = find_resource(channel_id);
	size_t n = 0;

	if (resource) {
		for (n = 0; n < resource->rd_count; n++)
			if (n == scmi_id)
				return &resource->rd[n];
	}

	return NULL;
}

const char *plat_scmi_rd_get_name(unsigned int channel_id, unsigned int scmi_id)
{
	const struct stm32_scmi_rd *rd = find_rd(channel_id, scmi_id);

	if (!rd)
		return NULL;

	return rd->name;
}

size_t plat_scmi_rd_count(unsigned int channel_id)
{
	const struct channel_resources *resource = find_resource(channel_id);

	if (!resource)
		return 0;

	return resource->rd_count;
}

int32_t plat_scmi_rd_autonomous(unsigned int channel_id, unsigned int scmi_id,
				uint32_t state)
{
	const struct stm32_scmi_rd *rd = find_rd(channel_id, scmi_id);

	if (!rd)
		return SCMI_NOT_FOUND;

	if (!rd->rstctrl || !stm32mp_nsec_can_access_reset(rd->reset_id))
		return SCMI_DENIED;
	assert(rd->rstctrl);

#ifdef CFG_STM32MP15
	if (rd->reset_id == MCU_HOLD_BOOT_R)
		return SCMI_NOT_SUPPORTED;
#endif

	/* Supports only reset with context loss */
	if (state)
		return SCMI_NOT_SUPPORTED;

	FMSG("SCMI reset %u cycle", scmi_id);

	if (rstctrl_assert_to(rd->rstctrl, TIMEOUT_US_1MS))
		return SCMI_HARDWARE_ERROR;

	if (rstctrl_deassert_to(rd->rstctrl, TIMEOUT_US_1MS))
		return SCMI_HARDWARE_ERROR;

	return SCMI_SUCCESS;
}

int32_t plat_scmi_rd_set_state(unsigned int channel_id, unsigned int scmi_id,
			       bool assert_not_deassert)
{
	const struct stm32_scmi_rd *rd = find_rd(channel_id, scmi_id);
	TEE_Result res = TEE_ERROR_GENERIC;

	if (!rd)
		return SCMI_NOT_FOUND;

	if (!rd->rstctrl || !stm32mp_nsec_can_access_reset(rd->reset_id))
		return SCMI_DENIED;
	assert(rd->rstctrl);

	if (assert_not_deassert) {
		FMSG("SCMI reset %u set", scmi_id);
		res = rstctrl_assert(rd->rstctrl);
	} else {
		FMSG("SCMI reset %u release", scmi_id);
		res = rstctrl_deassert(rd->rstctrl);
	}

	if (res)
		return SCMI_HARDWARE_ERROR;

	return SCMI_SUCCESS;
}

/*
 * Platform SCMI voltage domains
 */
static struct stm32_scmi_voltd *find_voltd(unsigned int channel_id,
					   unsigned int scmi_id)
{
	const struct channel_resources *resource = find_resource(channel_id);
	size_t n = 0;

	if (resource) {
		for (n = 0; n < resource->voltd_count; n++)
			if (n == scmi_id)
				return &resource->voltd[n];
	}

	return NULL;
}

size_t plat_scmi_voltd_count(unsigned int channel_id)
{
	const struct channel_resources *resource = find_resource(channel_id);

	if (!resource)
		return 0;

	return resource->voltd_count;
}

const char *plat_scmi_voltd_get_name(unsigned int channel_id,
				     unsigned int scmi_id)
{
	struct stm32_scmi_voltd *voltd = find_voltd(channel_id, scmi_id);

	/* Currently non-secure is allowed to access all PWR regulators */
	if (!voltd)
		return NULL;

	return voltd->name;
}

static enum pwr_regulator pwr_scmi_to_regu_id(struct stm32_scmi_voltd *voltd)
{
	if (!strcmp(voltd->priv_id, PWR_REG11_NAME_ID))
		return PWR_REG11;
	if (!strcmp(voltd->priv_id, PWR_REG18_NAME_ID))
		return PWR_REG18;
	if (!strcmp(voltd->priv_id, PWR_USB33_NAME_ID))
		return PWR_USB33;

	panic();
}

static long stub_get_level_uv(struct stm32_scmi_voltd *voltd)
{
	if (!strcmp(voltd->priv_id, STUB_SDMMC1_IO_NAME_ID) ||
	    !strcmp(voltd->priv_id, STUB_SDMMC2_IO_NAME_ID))
		return 3300000;

	panic();
}

static int32_t stub_describe_levels(struct stm32_scmi_voltd *voltd __unused,
				    size_t start_index, long *microvolt,
				    size_t *nb_elts)
{
	if (start_index)
		return SCMI_INVALID_PARAMETERS;

	if (!microvolt || !*nb_elts) {
		*nb_elts = 1;
		return SCMI_SUCCESS;
	}

	microvolt[0] = stub_get_level_uv(voltd);
	*nb_elts = 1;

	return SCMI_SUCCESS;
}

int32_t plat_scmi_voltd_levels_array(unsigned int channel_id,
				     unsigned int scmi_id, size_t start_index,
				     long *levels, size_t *nb_elts)

{
	struct stm32_scmi_voltd *voltd = find_voltd(channel_id, scmi_id);

	if (!voltd)
		return SCMI_NOT_FOUND;

	if (voltd->regulator) {
		struct regulator_voltages *voltages = NULL;
		TEE_Result res = TEE_ERROR_GENERIC;
		int *ref = NULL;
		size_t ref_count = 0;
		size_t n = 0;

		res = regulator_supported_voltages(voltd->regulator, &voltages);
		if (res == TEE_ERROR_NOT_SUPPORTED)
			return SCMI_NOT_SUPPORTED;
		if (res)
			return SCMI_GENERIC_ERROR;
		if (!voltages || voltages->type != VOLTAGE_TYPE_FULL_LIST) {
			/*
			 * Triplet min/max/step description. Caller should use
			 * plat_scmi_voltd_levels_by_step().
			 */
			return SCMI_NOT_SUPPORTED;
		}

		ref = voltages->entries;
		ref_count = voltages->num_levels;

		/* Bound according to regulator registered min/max levels */
		for (n = ref_count; n > 0; n--)
			if (voltages->entries[n - 1] > voltd->regulator->max_uv)
				ref_count--;
		for (n = 0; n < ref_count; n++)
			if (voltages->entries[n] >= voltd->regulator->min_uv)
				break;

		if (n == ref_count) {
			DMSG("Voltage list out of regulator %s level bounds",
			     regulator_name(voltd->regulator));
			return SCMI_GENERIC_ERROR;
		}

		if (start_index >= ref_count)
			return SCMI_OUT_OF_RANGE;

		if (!*nb_elts) {
			*nb_elts = ref_count - start_index;
			return SCMI_SUCCESS;
		}

		for (n = 0; n < *nb_elts; n++)
			levels[n] = ref[start_index + n];

		return SCMI_SUCCESS;
	}

	switch (voltd->priv_dev) {
	case VOLTD_STUB:
		return stub_describe_levels(voltd, start_index, levels,
					    nb_elts);
	default:
		return SCMI_DENIED;
	}
}

int32_t plat_scmi_voltd_levels_by_step(unsigned int channel_id,
				       unsigned int scmi_id, long *min_max_step)
{
	struct stm32_scmi_voltd *voltd = find_voltd(channel_id, scmi_id);

	if (!voltd)
		return SCMI_NOT_FOUND;

	if (voltd->regulator) {
		struct regulator_voltages *voltages = NULL;
		TEE_Result res = TEE_ERROR_GENERIC;
		int ref_min = 0;
		int ref_max = 0;
		int ref_step = 0;

		res = regulator_supported_voltages(voltd->regulator, &voltages);
		if (res == TEE_ERROR_NOT_SUPPORTED)
			return SCMI_NOT_SUPPORTED;
		if (res)
			return SCMI_GENERIC_ERROR;
		if (!voltages || voltages->type != VOLTAGE_TYPE_INCREMENT) {
			/*
			 * Triplet min/max/step description. Caller should use
			 * plat_scmi_voltd_levels_by_step().
			 */
			return SCMI_NOT_SUPPORTED;
		}

		ref_min = voltages->entries[0];
		ref_max = voltages->entries[1];
		ref_step = voltages->entries[2];

		if (ref_min < voltd->regulator->min_uv) {
			int diff = voltd->regulator->min_uv - ref_min;
			int incr = DIV_ROUND_UP(diff, ref_step);

			ref_min += ref_step * incr;
		}

		if (ref_max > voltd->regulator->max_uv) {
			int diff = ref_max - voltd->regulator->max_uv;
			int decr = diff / ref_step;

			ref_max -= ref_step * decr;
		}

		min_max_step[0] = ref_min;
		min_max_step[1] = ref_max;
		min_max_step[2] = ref_step;

		return SCMI_SUCCESS;
	}

	return SCMI_NOT_SUPPORTED;
}

int32_t plat_scmi_voltd_get_level(unsigned int channel_id, unsigned int scmi_id,
				  long *level_uv)
{
	struct stm32_scmi_voltd *voltd = find_voltd(channel_id, scmi_id);

	if (!voltd)
		return SCMI_INVALID_PARAMETERS;

	if (voltd->regulator) {
		*level_uv = regulator_get_voltage(voltd->regulator);
		return SCMI_SUCCESS;
	}

	switch (voltd->priv_dev) {
	case VOLTD_STUB:
		*level_uv = stub_get_level_uv(voltd);
		return SCMI_SUCCESS;
	default:
		return SCMI_DENIED;
	}
}

int32_t plat_scmi_voltd_set_level(unsigned int channel_id, unsigned int scmi_id,
				  long level_uv)
{
	struct stm32_scmi_voltd *voltd = find_voltd(channel_id, scmi_id);

	if (!voltd)
		return SCMI_NOT_FOUND;

	if (voltd->regulator) {
		TEE_Result res = TEE_ERROR_GENERIC;

		if (level_uv < INT_MIN || level_uv > INT_MAX)
			return SCMI_OUT_OF_RANGE;

		res = regulator_set_voltage(voltd->regulator, level_uv);
		if (res)
			return SCMI_GENERIC_ERROR;
		else
			return SCMI_SUCCESS;
	}

	switch (voltd->priv_dev) {
	case VOLTD_STUB:
		return SCMI_SUCCESS;
	default:
		return SCMI_DENIED;
	}
}

int32_t plat_scmi_voltd_get_config(unsigned int channel_id,
				   unsigned int scmi_id, uint32_t *config)
{
	struct stm32_scmi_voltd *voltd = find_voltd(channel_id, scmi_id);

	if (!voltd)
		return SCMI_NOT_FOUND;

	if (voltd->regulator) {
		if (voltd->state)
			*config = SCMI_VOLTAGE_DOMAIN_CONFIG_ARCH_ON;
		else
			*config = SCMI_VOLTAGE_DOMAIN_CONFIG_ARCH_OFF;

		return SCMI_SUCCESS;
	}

	switch (voltd->priv_dev) {
	case VOLTD_STUB:
		*config = SCMI_VOLTAGE_DOMAIN_CONFIG_ARCH_ON;
		return SCMI_SUCCESS;
	default:
		return SCMI_DENIED;
	}
}

int32_t plat_scmi_voltd_set_config(unsigned int channel_id,
				   unsigned int scmi_id, uint32_t config)
{
	struct stm32_scmi_voltd *voltd = find_voltd(channel_id, scmi_id);

	if (!voltd)
		return SCMI_NOT_FOUND;

	if (voltd->regulator) {
		TEE_Result res = TEE_ERROR_GENERIC;

		if (config == SCMI_VOLTAGE_DOMAIN_CONFIG_ARCH_ON &&
		    !voltd->state) {
			res = regulator_enable(voltd->regulator);
			if (!res)
				voltd->state = true;
		} else if (config == SCMI_VOLTAGE_DOMAIN_CONFIG_ARCH_OFF &&
			 voltd->state) {
			res = regulator_disable(voltd->regulator);
			if (!res)
				voltd->state = false;
		} else {
			res = TEE_ERROR_GENERIC;
		}

		if (res)
			return SCMI_GENERIC_ERROR;
		else
			return SCMI_SUCCESS;
	}

	switch (voltd->priv_dev) {
	case VOLTD_STUB:
		return SCMI_SUCCESS;
	default:
		return SCMI_DENIED;
	}
}

static void get_voltd_regulator(struct stm32_scmi_voltd *voltd)
{
	enum pwr_regulator regu_id = PWR_REGU_COUNT;

	switch (voltd->priv_dev) {
	case VOLTD_PWR:
		regu_id = pwr_scmi_to_regu_id(voltd);
		voltd->regulator = stm32mp1_pwr_get_regulator(regu_id);
		break;
	case VOLTD_PMIC:
		voltd->regulator = stm32mp_pmic_get_regulator(voltd->priv_id);
		break;
	case VOLTD_VREFBUF:
		voltd->regulator = stm32_vrefbuf_regulator();
		break;
	case VOLTD_STUB:
		break;
	default:
		break;
	}

	if (voltd->regulator && voltd->regulator->flags & REGULATOR_BOOT_ON)
		regulator_enable(voltd->regulator);
}

/*
 * Initialize platform SCMI resources
 */
static TEE_Result stm32mp1_init_scmi_server(void)
{
	size_t i = 0;
	size_t j = 0;

	for (i = 0; i < ARRAY_SIZE(scmi_channel); i++) {
		const struct channel_resources *res = scmi_channel + i;
		struct scmi_msg_channel *chan = res->channel;

		if (chan->shm_addr.pa) {
			struct io_pa_va *addr = &chan->shm_addr;

			/* Enforce non-secure shm mapped as device memory */
			addr->va = (vaddr_t)phys_to_virt(addr->pa,
							 MEM_AREA_IO_NSEC,
							 chan->shm_size);
			assert(addr->va);

			scmi_smt_init_agent_channel(chan);
		}

		for (j = 0; j < res->clock_count; j++) {
			struct stm32_scmi_clk *clk = &res->clock[j];

			if (!clk->name ||
			    strlen(clk->name) >= SCMI_CLOCK_NAME_SIZE)
				panic("SCMI clock name invalid");

			clk->clk = stm32mp_rcc_clock_id_to_clk(clk->clock_id);
			assert(clk->clk);

			/* Sync SCMI clocks with their targeted initial state */
			if (clk->enabled &&
			    stm32mp_nsec_can_access_clock(clk->clock_id))
				clk_enable(clk->clk);
		}

		for (j = 0; j < res->rd_count; j++) {
			struct stm32_scmi_rd *rd = &res->rd[j];
			struct rstctrl *rstctrl = NULL;

			if (!rd->name ||
			    strlen(rd->name) >= SCMI_RD_NAME_SIZE)
				panic("SCMI reset domain name invalid");

			if (stm32mp_nsec_can_access_clock(rd->reset_id))
				continue;

			rstctrl = stm32mp_rcc_reset_id_to_rstctrl(rd->reset_id);
			assert(rstctrl);
			if (rstctrl_get_exclusive(rstctrl))
				continue;

			rd->rstctrl = rstctrl;
		}

		for (j = 0; j < res->voltd_count; j++) {
			struct stm32_scmi_voltd *voltd = &res->voltd[j];

			if (!voltd->name ||
			    strlen(voltd->name) >= SCMI_VOLTD_NAME_SIZE)
				panic("SCMI voltage domain name invalid");

			get_voltd_regulator(voltd);
		}
	}

	return TEE_SUCCESS;
}

driver_init_late(stm32mp1_init_scmi_server);
