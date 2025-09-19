// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2021-2025, STMicroelectronics
 */

#include <crypto/crypto.h>
#include <drivers/clk.h>
#include <drivers/clk_dt.h>
#include <drivers/gpio.h>
#include <drivers/stm32_gpio.h>
#include <drivers/stm32_rif.h>
#include <drivers/stm32_rtc.h>
#include <drivers/stm32mp_dt_bindings.h>
#include <io.h>
#include <kernel/dt.h>
#include <kernel/dt_driver.h>
#include <kernel/interrupt.h>
#include <libfdt.h>
#include <mm/core_memprot.h>
#include <stdbool.h>
#include <stm32_util.h>

/* STM32 Registers */
#define _TAMP_CR1			0x00U
#define _TAMP_CR2			0x04U
#define _TAMP_CR3			0x08U
#define _TAMP_FLTCR			0x0CU
#define _TAMP_ATCR1			0x10U
#define _TAMP_ATSEEDR			0x14U
#define _TAMP_ATOR			0x18U
#define _TAMP_ATCR2			0x1CU
#define _TAMP_SECCFGR			0x20U
#define _TAMP_SMCR			0x20U
#define _TAMP_PRIVCFGR			0x24U
#define _TAMP_IER			0x2CU
#define _TAMP_SR			0x30U
#define _TAMP_MISR			0x34U
#define _TAMP_SMISR			0x38U
#define _TAMP_SCR			0x3CU
#define _TAMP_COUNTR			0x40U
#define _TAMP_COUNT2R			0x44U
#define _TAMP_OR			0x50U
#define _TAMP_ERCFGR			0X54U
#define _TAMP_BKPRIFR(x)		(0x70U + 0x4U * ((x) - 1U))
#define _TAMP_CIDCFGR(x)		(0x80U + 0x4U * (x))
#define _TAMP_BKPxR(x)			(0x100U + 0x4U * ((x) - 1U))
#define _TAMP_HWCFGR2			0x3ECU
#define _TAMP_HWCFGR1			0x3F0U
#define _TAMP_VERR			0x3F4U
#define _TAMP_IPIDR			0x3F8U
#define _TAMP_SIDR			0x3FCU

/* _TAMP_SECCFGR bit fields */
#define _TAMP_SECCFGR_BKPRWSEC_MASK	GENMASK_32(7, 0)
#define _TAMP_SECCFGR_BKPRWSEC_SHIFT	0U
#define _TAMP_SECCFGR_CNT2SEC		BIT(14)
#define _TAMP_SECCFGR_CNT2SEC_SHIFT	14U
#define _TAMP_SECCFGR_CNT1SEC		BIT(15)
#define _TAMP_SECCFGR_CNT1SEC_SHIFT	15U
#define _TAMP_SECCFGR_BKPWSEC_MASK	GENMASK_32(23, 16)
#define _TAMP_SECCFGR_BKPWSEC_SHIFT	16U
#define _TAMP_SECCFGR_BHKLOCK		BIT(30)
#define _TAMP_SECCFGR_TAMPSEC		BIT(31)
#define _TAMP_SECCFGR_TAMPSEC_SHIFT	31U
#define _TAMP_SECCFGR_BUT_BKP_MASK	(GENMASK_32(31, 30) | \
					 GENMASK_32(15, 14))
#define _TAMP_SECCFGR_RIF_TAMP_SEC	BIT(0)
#define _TAMP_SECCFGR_RIF_COUNT_1	BIT(1)
#define _TAMP_SECCFGR_RIF_COUNT_2	BIT(2)

/* _TAMP_SMCR bit fields */
#define _TAMP_SMCR_BKPRWDPROT_MASK	GENMASK_32(7, 0)
#define _TAMP_SMCR_BKPRWDPROT_SHIFT	0U
#define _TAMP_SMCR_BKPWDPROT_MASK	GENMASK_32(23, 16)
#define _TAMP_SMCR_BKPWDPROT_SHIFT	16U
#define _TAMP_SMCR_DPROT		BIT(31)
/*
 * _TAMP_PRIVCFGR bit fields
 */
#define _TAMP_PRIVCFG_CNT2PRIV		BIT(14)
#define _TAMP_PRIVCFG_CNT1PRIV		BIT(15)
#define _TAMP_PRIVCFG_BKPRWPRIV		BIT(29)
#define _TAMP_PRIVCFG_BKPWPRIV		BIT(30)
#define _TAMP_PRIVCFG_TAMPPRIV		BIT(31)
#define _TAMP_PRIVCFGR_MASK		(GENMASK_32(31, 29) | \
					 GENMASK_32(15, 14))
#define _TAMP_PRIVCFGR_RIF_TAMP_PRIV	BIT(0)
#define _TAMP_PRIVCFGR_RIF_R1		BIT(1)
#define _TAMP_PRIVCFGR_RIF_R2		BIT(2)

/* _TAMP_PRIVCFGR bit fields */
#define _TAMP_PRIVCFG_CNT2PRIV		BIT(14)
#define _TAMP_PRIVCFG_CNT1PRIV		BIT(15)
#define _TAMP_PRIVCFG_BKPRWPRIV		BIT(29)
#define _TAMP_PRIVCFG_BKPWPRIV		BIT(30)
#define _TAMP_PRIVCFG_TAMPPRIV		BIT(31)
#define _TAMP_PRIVCFGR_MASK		(GENMASK_32(31, 29) | \
					 GENMASK_32(15, 14))

/*_TAMP_CR1 bit fields */
#define _TAMP_CR1_ITAMP(id)		BIT((id) - INT_TAMP1 + U(16))
#define _TAMP_CR1_ETAMP(id)		BIT((id) - EXT_TAMP1)

/* _TAMP_CR2 bit fields */
#define _TAMP_CR2_ETAMPTRG(id)		BIT((id) - EXT_TAMP1 + U(24))
#define _TAMP_CR2_BKERASE		BIT(23)
#define _TAMP_CR2_BKBLOCK		BIT(22)
#define _TAMP_CR2_ETAMPMSK_MAX_ID	3U
#define _TAMP_CR2_ETAMPMSK(id)		BIT((id) - EXT_TAMP1 + U(16))
#define _TAMP_CR2_ETAMPNOER(id)		BIT((id) - EXT_TAMP1)

/* _TAMP_CR3 bit fields */
#define _TAMP_CR3_ITAMPNOER_ALL		GENMASK_32(12, 0)
#define _TAMP_CR3_ITAMPNOER(id)		BIT((id) - INT_TAMP1)

/* _TAMP_FLTCR bit fields */
#define _TAMP_FLTCR_TAMPFREQ_MASK	GENMASK_32(2, 0)
#define _TAMP_FLTCR_TAMPFREQ_SHIFT	0U
#define _TAMP_FLTCR_TAMPFLT_MASK	GENMASK_32(4, 3)
#define _TAMP_FLTCR_TAMPFLT_SHIFT	U(3)
#define _TAMP_FLTCR_TAMPPRCH_MASK	GENMASK_32(6, 5)
#define _TAMP_FLTCR_TAMPPRCH_SHIFT	5U
#define _TAMP_FLTCR_TAMPPUDIS		BIT(7)

/* _TAMP_ATCR bit fields */
#define _TAMP_ATCR1_ATCKSEL_MASK	GENMASK_32(19, 16)
#define _TAMP_ATCR1_ATCKSEL_SHIFT	16U
#define _TAMP_ATCR1_ATPER_MASK		GENMASK_32(26, 24)
#define _TAMP_ATCR1_ATPER_SHIFT		24U
#define _TAMP_ATCR1_ATOSHARE		BIT(30)
#define _TAMP_ATCR1_FLTEN		BIT(31)
#define _TAMP_ATCR1_COMMON_MASK		GENMASK_32(31, 16)
#define _TAMP_ATCR1_ETAMPAM(id)		BIT((id) - EXT_TAMP1)
#define _TAMP_ATCR1_ATOSEL_MASK(id) \
	({ \
		typeof(id) _id = (id); \
		GENMASK_32(((_id) - EXT_TAMP1 + 1) * 2 + 7, \
			   ((_id) - EXT_TAMP1) * 2 + 8); \
	})

#define _TAMP_ATCR1_ATOSEL(id, od) \
	SHIFT_U32((od) - OUT_TAMP1, ((id) - EXT_TAMP1) * 2 + 8)

/* _TAMP_ATCR2 bit fields */
#define _TAMP_ATCR2_ATOSEL_MASK(id) \
	({ \
		typeof(id) _id = (id); \
		GENMASK_32(((_id) - EXT_TAMP1 + 1) * 3 + 7, \
			   ((_id) - EXT_TAMP1) * 3 + 8); \
	})

#define _TAMP_ATCR2_ATOSEL(id, od) \
	SHIFT_U32((od) - OUT_TAMP1, ((id) - EXT_TAMP1) * 3 + 8)

/* _TAMP_ATOR bit fields */
#define _TAMP_PRNG			GENMASK_32(7, 0)
#define _TAMP_SEEDF			BIT(14)
#define _TAMP_INITS			BIT(15)

/* _TAMP_IER bit fields */
#define _TAMP_IER_ITAMP(id)		BIT((id) - INT_TAMP1 + U(16))
#define _TAMP_IER_ETAMP(id)		BIT((id) - EXT_TAMP1)

/* _TAMP_SR bit fields */
#define _TAMP_SR_ETAMPXF_MASK		GENMASK_32(7, 0)
#define _TAMP_SR_ITAMPXF_MASK		GENMASK_32(31, 16)
#define _TAMP_SR_ITAMP(id)		BIT((id) - INT_TAMP1 + U(16))
#define _TAMP_SR_ETAMP(id)		BIT((id) - EXT_TAMP1)

/* _TAMP_SCR bit fields */
#define _TAMP_SCR_ITAMP(id)		BIT((id) - INT_TAMP1 + U(16))
#define _TAMP_SCR_ETAMP(id)		BIT((id) - EXT_TAMP1)

/* _TAMP_OR bit fields */
#define _TAMP_OR_STM32MP13_IN1RMP_PF10	0U
#define _TAMP_OR_STM32MP13_IN1RMP_PC13	BIT(0)
#define _TAMP_OR_STM32MP13_IN2RMP_PA6	0U
#define _TAMP_OR_STM32MP13_IN2RMP_PI1	BIT(1)
#define _TAMP_OR_STM32MP13_IN3RMP_PC0	0U
#define _TAMP_OR_STM32MP13_IN3RMP_PI2	BIT(2)
#define _TAMP_OR_STM32MP13_IN4RMP_PG8	0U
#define _TAMP_OR_STM32MP13_IN4RMP_PI3	BIT(3)

/* For STM32MP15x, _TAMP_CFGR is _TAMP_OR */
#define _TAMP_OR_STM32MP15_OUT3RMP_PI8	0U
#define _TAMP_OR_STM32MP15_OUT3RMP_PC13	BIT(0)

#define _TAMP_STM32MP21_OR_IN1RMP_PC4	0U
#define _TAMP_STM32MP21_OR_IN1RMP_PI8	BIT(0)

#define _TAMP_OR_STM32MP25_IN1RMP_PC4	0U
#define _TAMP_OR_STM32MP25_IN1RMP_PI8	BIT(0)
#define _TAMP_OR_STM32MP25_IN3RMP_PC3	0U
#define _TAMP_OR_STM32MP25_IN3RMP_PZ2	BIT(1)
#define _TAMP_OR_STM32MP25_IN5RMP_PF6	0U
#define _TAMP_OR_STM32MP25_IN5RMP_PZ4	BIT(2)

/* _TAMP_HWCFGR2 bit fields */
#define _TAMP_HWCFGR2_TZ		GENMASK_32(11, 8)
#define _TAMP_HWCFGR2_OR		GENMASK_32(7, 0)

/* _TAMP_HWCFGR1 bit fields */
#define _TAMP_HWCFGR1_BKPREG		GENMASK_32(7, 0)
#define _TAMP_HWCFGR1_TAMPER_SHIFT	8U
#define _TAMP_HWCFGR1_TAMPER		GENMASK_32(11, 8)
#define _TAMP_HWCFGR1_ACTIVE		GENMASK_32(15, 12)
#define _TAMP_HWCFGR1_INTERN		GENMASK_32(31, 16)
#define _TAMP_HWCFGR1_ITAMP_MAX_ID	16U
#define _TAMP_HWCFGR1_ITAMP(id)		BIT((id) - INT_TAMP1 + 16U)

/* _TAMP_VERR bit fields */
#define _TAMP_VERR_MINREV		GENMASK_32(3, 0)
#define _TAMP_VERR_MAJREV		GENMASK_32(7, 4)

/*
 * CIDCFGR register bitfields
 */
#define _TAMP_CIDCFGR_SCID_MASK		GENMASK_32(6, 4)
#define _TAMP_CIDCFGR_CONF_MASK		(_CIDCFGR_CFEN |	 \
					 _CIDCFGR_SEMEN |	 \
					 _TAMP_CIDCFGR_SCID_MASK)

/* _TAMP_BKPRIFR */
#define _TAMP_BKPRIFR_1_MASK		GENMASK_32(7, 0)
#define _TAMP_BKPRIFR_2_MASK		GENMASK_32(7, 0)
#define _TAMP_BKPRIFR_3_MASK		(GENMASK_32(23, 16) | GENMASK_32(7, 0))
#define _TAMP_BKPRIFR_ZONE3_RIF2_SHIFT	16U

/*
 * RIF miscellaneous
 */
#define TAMP_NB_BKPR_ZONES		3U
#define TAMP_RIF_RESOURCES		3U
#define TAMP_RIF_OFFSET_CNT		4U

/*
 * Compatibility capabilities
 * TAMP_HAS_REGISTER_SECCFGR - Supports SECCFGR, otherwise supports SMCR
 * register
 * TAMP_HAS_REGISTER_PRIVCFG - Supports PRIVCFGR configuration register
 * TAMP_HAS_RIF_SUPPORT - Supports RIF
 */
#define TAMP_HAS_REGISTER_SECCFGR	BIT(0)
#define TAMP_HAS_REGISTER_PRIVCFGR	BIT(1)
#define TAMP_HAS_REGISTER_ERCFGR	BIT(2)
#define TAMP_HAS_REGISTER_ATCR2		BIT(3)
#define TAMP_HAS_REGISTER_CR3		BIT(4)
#define TAMP_HAS_CR2_SECRET_STATUS	BIT(5)
#define TAMP_SIZE_ATCR1_ATCKSEL_IS_4	BIT(7)
#define TAMP_HAS_RIF_SUPPORT		BIT(31)

/* Tamper event modes */
#define TAMP_ERASE			0x0U
#define TAMP_NOERASE			BIT(1)
#define TAMP_NO_EVT_MASK		0x0U
#define TAMP_EVT_MASK			BIT(2)
#define TAMP_MODE_MASK			GENMASK_32(15, 0)

/* Callback return bitmask values */
#define TAMP_CB_ACK			BIT(0)
#define TAMP_CB_RESET			BIT(1)
#define TAMP_CB_ACK_AND_RESET		(TAMP_CB_RESET | TAMP_CB_ACK)

#define SEED_TIMEOUT_US			1000U

/* Define TAMPER modes from DT */
#define TAMP_TRIG_ON			BIT(16)
#define TAMP_ACTIVE			BIT(17)
#define TAMP_IN_DT			BIT(18)

enum stm32_tamp_id {
	INT_TAMP1 = 0,
	INT_TAMP2,
	INT_TAMP3,
	INT_TAMP4,
	INT_TAMP5,
	INT_TAMP6,
	INT_TAMP7,
	INT_TAMP8,
	INT_TAMP9,
	INT_TAMP10,
	INT_TAMP11,
	INT_TAMP12,
	INT_TAMP13,
	INT_TAMP14,
	INT_TAMP15,
	INT_TAMP16,

	EXT_TAMP1,
	EXT_TAMP2,
	EXT_TAMP3,
	EXT_TAMP4,
	EXT_TAMP5,
	EXT_TAMP6,
	EXT_TAMP7,
	EXT_TAMP8,

	LAST_TAMP,
	INVALID_TAMP = 0xFFFF,
};

enum stm32_tamp_out_id {
	OUT_TAMP1 = LAST_TAMP,
	OUT_TAMP2,
	OUT_TAMP3,
	OUT_TAMP4,
	OUT_TAMP5,
	OUT_TAMP6,
	OUT_TAMP7,
	OUT_TAMP8,
	INVALID_OUT_TAMP = INVALID_TAMP
};

/**
 * struct stm32_tamp_pin_map - Tamper pin map
 *
 * @id: Identifier of the tamper
 * @conf: Internal mux configuration of the pin present in the TAMP block
 * @bank: GPIO pin bank
 * @pin: GPIO number in the bank
 * @out: True if pin is used for tamper output
 */
struct stm32_tamp_pin_map {
	uint32_t id;
	uint32_t conf;
	uint8_t bank;
	uint8_t pin;
	bool out;
};

/**
 * struct stm32_tamp_tamper_data - Tamper data
 *
 * @id: Identifier of the tamper
 * @out_id: Identifier of the output tamper, tamper in active mode
 * @mode: Mode of the tamper
 * @func: Tamper callback in case of tamper event
 */
struct stm32_tamp_tamper_data {
	uint32_t id;
	uint32_t out_id;
	uint32_t mode;
	uint32_t (*func)(int id);
};

/**
 * struct stm32_tamp_compat - TAMP compatible data
 *
 * @ext_tamp: List of available external tampers
 * @int_tamp: List of available internal tampers
 * @pin_map: List of hardware mapped of pins supporting tamper event detection
 * @nb_monotonic_counter: Number of monotic counter supported
 * @ext_tamp_size: Size of @ext_tamp
 * @int_tamp_size: Size of @int_tamp
 * @pin_map_size: Size of pin_map
 * @tags: Bit flags TAMP_HAS_* for compatibility management
 */
struct stm32_tamp_compat {
	struct stm32_tamp_tamper_data *ext_tamp;
	struct stm32_tamp_tamper_data *int_tamp;
	const struct stm32_tamp_pin_map *pin_map;
	int nb_monotonic_counter;
	uint32_t ext_tamp_size;
	uint32_t int_tamp_size;
	uint32_t pin_map_size;
	uint32_t tags;
};

/*
 * struct stm32_bkpregs_conf - Backup registers zone bounds
 * @zone1_end - Number of backup registers in zone 1
 * @zone2_end - Number of backup registers in zone 2 + zone 1
 * @rif_offsets - RIF offsets used for CID compartments
 *
 * TAMP backup registers access permissions
 *
 * Zone 1: read/write in secure state, no access in non-secure state
 * Zone 2: read/write in secure state, read-only in non-secure state
 * Zone 3: read/write in secure state, read/write in non-secure state
 *
 * Protection zone 1
 * If zone1_end == 0 no backup register are in zone 1.
 * Otherwise backup registers from TAMP_BKP0R to TAMP_BKP<x>R are in zone 1,
 * with <x> = (@zone1_end - 1).
 *
 * Protection zone 2
 * If zone2_end == 0 no backup register are in zone 2 and zone 1.
 * Otherwise backup registers from TAMP_BKP<y>R to TAMP_BKP<z>R are in zone 2,
 * with <y> = @zone1_end and <z> = (@zone2_end - 1).
 *
 * Protection zone 3
 * Backup registers from TAMP_BKP<t>R to last backup register are in zone 3,
 * with <t> = (@zone2_end - 1).
 *
 * When RIF is supported, each zone can be subdivided to restrain accesses to
 * some CIDs.
 */
struct stm32_bkpregs_conf {
	uint32_t zone1_end;
	uint32_t zone2_end;
	uint32_t *rif_offsets;
};

/**
 * struct stm32_tamp_platdata - TAMP platform data
 * @base: IOMEM base address
 * @bkpregs_conf: TAMP backup register configuration reference
 * @compat: Reference to compat data passed at driver initialization
 * @conf_data: RIF configuration data
 * @clock: TAMP clock
 * @itr: TAMP interrupt handler
 * @nb_rif_resources: Number of RIF resources
 * @passive_conf: Passive tampers configuration
 * @active_conf: Active tampers configuration
 * @pins_conf: Configuration of mapped pins for tampers
 * @out_pins: Output pins for passive tampers
 * @is_wakeup_source: True if a tamper event is a wakeup source
 * @is_tdcid: True if current processor is TDCID
 */
struct stm32_tamp_platdata {
	struct io_pa_va base;
	struct stm32_bkpregs_conf bkpregs_conf;
	struct stm32_tamp_compat *compat;
	struct rif_conf_data *conf_data;
	struct clk *clock;
	struct itr_handler *itr;
	unsigned int nb_rif_resources;
	uint32_t passive_conf;
	uint32_t active_conf;
	uint32_t pins_conf;
	uint32_t out_pins;
	bool is_wakeup_source;
	bool is_tdcid;
};

/**
 * struct stm32_tamp_instance - TAMP instance data
 * @pdata: TAMP platform data
 * @hwconf1: Copy of TAMP HWCONF1 register content
 * @hwconf2: Copy of TAMP HWCONF2 register content
 */
struct stm32_tamp_instance {
	struct stm32_tamp_platdata pdata;
	uint32_t hwconf1;
	uint32_t hwconf2;
};

#define GPIO_BANK(port)	 ((port) - 'A')

#if defined(CFG_STM32MP13)
static const char * const itamper_name[] = {
	[INT_TAMP1] = "Backup domain voltage threshold monitoring",
	[INT_TAMP2] = "Temperature monitoring",
	[INT_TAMP3] = "LSE monitoring",
	[INT_TAMP4] = "HSE monitoring",
	[INT_TAMP5] = "RTC Calendar overflow",
	[INT_TAMP6] = "JTAG SWD access",
	[INT_TAMP7] = "ADC2 analog watchdog monitoring 1",
	[INT_TAMP8] = "Monotonic counter 1",
	[INT_TAMP9] = "Cryptographic perpipheral fault",
	[INT_TAMP10] = "Monotonic counter 2",
	[INT_TAMP11] = "IWDG1 reset",
	[INT_TAMP12] = "ADC2 analog watchdog monitoring 2",
	[INT_TAMP13] = "ADC2 analog watchdog monitoring 3",
};

static struct stm32_tamp_tamper_data int_tamp_mp13[] = {
	{ .id = INT_TAMP1 }, { .id = INT_TAMP2 }, { .id = INT_TAMP3 },
	{ .id = INT_TAMP4 }, { .id = INT_TAMP5 }, { .id = INT_TAMP6 },
	{ .id = INT_TAMP7 }, { .id = INT_TAMP8 }, { .id = INT_TAMP9 },
	{ .id = INT_TAMP10 }, { .id = INT_TAMP11 },
	{ .id = INT_TAMP12 }, { .id = INT_TAMP13 },
};

static struct stm32_tamp_tamper_data ext_tamp_mp13[] = {
	{ .id = EXT_TAMP1 }, { .id = EXT_TAMP2 }, { .id = EXT_TAMP3 },
	{ .id = EXT_TAMP4 }, { .id = EXT_TAMP5 }, { .id = EXT_TAMP6 },
	{ .id = EXT_TAMP7 }, { .id = EXT_TAMP8 },
};

static const struct stm32_tamp_pin_map pin_map_mp13[] = {
	{
		.id = EXT_TAMP1, .bank = GPIO_BANK('C'), .pin = 13,
		.out = false, .conf = _TAMP_OR_STM32MP13_IN1RMP_PC13,
	},
	{
		.id = EXT_TAMP1, .bank = GPIO_BANK('F'), .pin = 10,
		.out = false, .conf = _TAMP_OR_STM32MP13_IN1RMP_PF10,
	},
	{
		.id = EXT_TAMP2, .bank = GPIO_BANK('A'), .pin = 6,
		.out = false, .conf = _TAMP_OR_STM32MP13_IN2RMP_PA6,
	},
	{
		.id = EXT_TAMP2, .bank = GPIO_BANK('I'), .pin = 1,
		.out = false, .conf = _TAMP_OR_STM32MP13_IN2RMP_PI1,
	},
	{
		.id = EXT_TAMP3, .bank = GPIO_BANK('C'), .pin = 0,
		.out = false, .conf = _TAMP_OR_STM32MP13_IN3RMP_PC0,
	},
	{
		.id = EXT_TAMP3, .bank = GPIO_BANK('I'), .pin = 2,
		.out = false, .conf = _TAMP_OR_STM32MP13_IN3RMP_PI2,
	},
	{
		.id = EXT_TAMP4, .bank = GPIO_BANK('G'), .pin = 8,
		.out = false, .conf = _TAMP_OR_STM32MP13_IN4RMP_PG8,
	},
	{
		.id = EXT_TAMP4, .bank = GPIO_BANK('I'), .pin = 3,
		.out = false, .conf = _TAMP_OR_STM32MP13_IN4RMP_PI3,
	},
};
#endif

#if defined(CFG_STM32MP15)
static const char * const itamper_name[] = {
	[INT_TAMP1] = "RTC power domain",
	[INT_TAMP2] = "Temperature monitoring",
	[INT_TAMP3] = "LSE monitoring",
	[INT_TAMP5] = "RTC Calendar overflow",
	[INT_TAMP8] = "Monotonic counter",
};
DECLARE_KEEP_PAGER(itamper_name);

static struct stm32_tamp_tamper_data int_tamp_mp15[] = {
	{ .id = INT_TAMP1 }, { .id = INT_TAMP2 }, { .id = INT_TAMP3 },
	{ .id = INT_TAMP4 }, { .id = INT_TAMP5 }, { .id = INT_TAMP8 },
};

static struct stm32_tamp_tamper_data ext_tamp_mp15[] = {
	{ .id = EXT_TAMP1 }, { .id = EXT_TAMP2 }, { .id = EXT_TAMP3 },
};

static const struct stm32_tamp_pin_map pin_map_mp15[] = {
	{
		.id = EXT_TAMP1, .bank = GPIO_BANK('C'), .pin = 13,
		.out = false, .conf = _TAMP_OR_STM32MP15_OUT3RMP_PI8,
	},
	{
		.id = EXT_TAMP2, .bank = GPIO_BANK('I'), .pin = 8,
		.out = false, .conf = _TAMP_OR_STM32MP15_OUT3RMP_PI8,
	},
	{
		.id = EXT_TAMP3, .bank = GPIO_BANK('C'), .pin = 1,
		.out = false, .conf = _TAMP_OR_STM32MP15_OUT3RMP_PI8,
	},
	{
		.id = OUT_TAMP2, .bank = GPIO_BANK('C'), .pin = 13,
		.out = true, .conf = _TAMP_OR_STM32MP15_OUT3RMP_PI8,
	},
	{
		.id = OUT_TAMP3, .bank = GPIO_BANK('C'), .pin = 13,
		.out = true, .conf = _TAMP_OR_STM32MP15_OUT3RMP_PC13,
	},
	{
		.id = OUT_TAMP3, .bank = GPIO_BANK('I'), .pin = 8,
		.out = true, .conf = _TAMP_OR_STM32MP15_OUT3RMP_PI8,
	},
};
#endif

#if defined(CFG_STM32MP21)
static const char * const itamper_name[] = {
	[INT_TAMP1] = "Backup domain voltage threshold monitoring",
	[INT_TAMP2] = "Temperature monitoring",
	[INT_TAMP3] = "LSE monitoring",
	[INT_TAMP4] = "HSE monitoring",
	[INT_TAMP5] = "RTC Calendar overflow",
	[INT_TAMP6] = "JTAG TAP access in secured-closed",
	[INT_TAMP7] = "ADC2 analog watchdog monitoring1",
	[INT_TAMP8] = "Monotonic counter 1 overflow",
	[INT_TAMP9] = "Cryptographic peripherals fault",
	[INT_TAMP10] = "Monotonic counter 2 overflow",
	[INT_TAMP11] = "IWDG3 reset",
	[INT_TAMP12] = "ADC2 analog watchdog monitoring2",
	[INT_TAMP13] = "ADC2 analog watchdog monitoring3",
	[INT_TAMP14] = "RIFSC or BSEC or DBGMCU fault",
	[INT_TAMP15] = "IWDG1_reset",
	[INT_TAMP16] = "BOOTROM fault",
};

static struct stm32_tamp_tamper_data int_tamp_mp21[] = {
	{ .id = INT_TAMP1 }, { .id = INT_TAMP2 }, { .id = INT_TAMP3 },
	{ .id = INT_TAMP4 }, { .id = INT_TAMP5 }, { .id = INT_TAMP6 },
	{ .id = INT_TAMP7 }, { .id = INT_TAMP8 }, { .id = INT_TAMP9 },
	{ .id = INT_TAMP10 }, { .id = INT_TAMP11 }, { .id = INT_TAMP12 },
	{ .id = INT_TAMP13 }, { .id = INT_TAMP14 }, { .id = INT_TAMP15 },
	{ .id = INT_TAMP16 },
};

static struct stm32_tamp_tamper_data ext_tamp_mp21[] = {
	{ .id = EXT_TAMP1 }, { .id = EXT_TAMP2 }, { .id = EXT_TAMP3 },
	{ .id = EXT_TAMP4 }, { .id = EXT_TAMP5 }, { .id = EXT_TAMP6 },
	{ .id = EXT_TAMP7 },
};

static const struct stm32_tamp_pin_map pin_map_mp21[] = {
	{
		.id = EXT_TAMP1, .bank = GPIO_BANK('I'), .pin = 8,
		.out = false, .conf = _TAMP_STM32MP21_OR_IN1RMP_PI8,
	},
	{
		.id = EXT_TAMP1, .bank = GPIO_BANK('C'), .pin = 4,
		.out = false, .conf = _TAMP_STM32MP21_OR_IN1RMP_PC4,
	},
};
#endif

#if defined(CFG_STM32MP25) || defined(CFG_STM32MP23)
static const char * const itamper_name[] = {
	[INT_TAMP1] = "Backup domain voltage threshold monitoring",
	[INT_TAMP2] = "Temperature monitoring",
	[INT_TAMP3] = "LSE monitoring",
	[INT_TAMP4] = "HSE monitoring",
	[INT_TAMP5] = "RTC Calendar overflow",
	[INT_TAMP6] = "JTAG/SWD access",
	[INT_TAMP7] = "VDDCORE monitoring under/over voltage",
	[INT_TAMP8] = "Monotonic counter 1 overflow",
	[INT_TAMP9] = "Cryptographic peripherals fault",
	[INT_TAMP10] = "Monotonic counter 2 overflow",
	[INT_TAMP11] = "IWDG3 reset",
	[INT_TAMP12] = "VDDCPU monitoring under/over voltage",
	[INT_TAMP14] = "IWDG5_reset",
	[INT_TAMP15] = "IWDG1_reset",
};

static struct stm32_tamp_tamper_data int_tamp_mp25[] = {
	{ .id = INT_TAMP1 }, { .id = INT_TAMP2 }, { .id = INT_TAMP3 },
	{ .id = INT_TAMP4 }, { .id = INT_TAMP5 }, { .id = INT_TAMP6 },
	{ .id = INT_TAMP7 }, { .id = INT_TAMP8 }, { .id = INT_TAMP9 },
	{ .id = INT_TAMP10 }, { .id = INT_TAMP11 },
	{ .id = INT_TAMP12 }, { .id = INT_TAMP14 },
	{ .id = INT_TAMP15 },
};

#ifdef CFG_STM32MP25
static struct stm32_tamp_tamper_data ext_tamp_mp25[] = {
	{ .id = EXT_TAMP1 }, { .id = EXT_TAMP2 }, { .id = EXT_TAMP3 },
	{ .id = EXT_TAMP4 }, { .id = EXT_TAMP5 }, { .id = EXT_TAMP6 },
	{ .id = EXT_TAMP7 }, { .id = EXT_TAMP8 },
};
#else
static struct stm32_tamp_tamper_data ext_tamp_mp23[] = {
	{ .id = EXT_TAMP1 }, { .id = EXT_TAMP2 }, { .id = EXT_TAMP3 },
	{ .id = EXT_TAMP4 }, { .id = EXT_TAMP5 }, { .id = EXT_TAMP6 },
	{ .id = EXT_TAMP7 },
};
#endif

static const struct stm32_tamp_pin_map pin_map_mp25[] = {
	{
		.id = EXT_TAMP1, .bank = GPIO_BANK('I'), .pin = 8,
		.out = false, .conf = _TAMP_OR_STM32MP25_IN1RMP_PI8,
	},
	{
		.id = EXT_TAMP1, .bank = GPIO_BANK('C'), .pin = 4,
		.out = false, .conf = _TAMP_OR_STM32MP25_IN1RMP_PC4,
	},
	{
		.id = EXT_TAMP3, .bank = GPIO_BANK('C'), .pin = 3,
		.out = false, .conf = _TAMP_OR_STM32MP25_IN3RMP_PC3,
	},
	{
		.id = EXT_TAMP3, .bank = GPIO_BANK('Z'), .pin = 2,
		.out = false, .conf = _TAMP_OR_STM32MP25_IN3RMP_PZ2,
	},
	{
		.id = EXT_TAMP5, .bank = GPIO_BANK('F'), .pin = 6,
		.out = false, .conf = _TAMP_OR_STM32MP25_IN5RMP_PF6,
	},
	{
		.id = EXT_TAMP5, .bank = GPIO_BANK('Z'), .pin = 4,
		.out = false, .conf = _TAMP_OR_STM32MP25_IN5RMP_PZ4,
	},
};
#endif

/* Expects at most a single instance */
static struct stm32_tamp_instance *stm32_tamp_dev;

static vaddr_t get_base(void)
{
	assert(stm32_tamp_dev && stm32_tamp_dev->pdata.base.pa);

	return io_pa_or_va_secure(&stm32_tamp_dev->pdata.base, 1);
}

static void apply_rif_config(void)
{
	struct rif_conf_data *rif_conf = stm32_tamp_dev->pdata.conf_data;
	uint32_t access_mask_priv_reg = 0;
	uint32_t access_mask_sec_reg = 0;
	vaddr_t base = get_base();
	uint32_t privcfgr = 0;
	uint32_t seccfgr = 0;
	unsigned int i = 0;

	if (!stm32_tamp_dev->pdata.conf_data)
		return;

	/* Build access masks for _TAMP_PRIVCFGR and _TAMP_SECCFGR */
	for (i = 0; i < TAMP_RIF_RESOURCES; i++) {
		if (BIT(i) & rif_conf->access_mask[0]) {
			switch (i) {
			case 0:
				access_mask_sec_reg |= _TAMP_SECCFGR_TAMPSEC;
				access_mask_priv_reg |= _TAMP_PRIVCFG_TAMPPRIV;
				break;
			case 1:
				access_mask_sec_reg |= _TAMP_SECCFGR_CNT1SEC;
				access_mask_priv_reg |= _TAMP_PRIVCFG_CNT1PRIV;
				access_mask_priv_reg |= _TAMP_PRIVCFG_BKPRWPRIV;
				break;
			case 2:
				access_mask_sec_reg |= _TAMP_SECCFGR_CNT2SEC;
				access_mask_priv_reg |= _TAMP_PRIVCFG_CNT2PRIV;
				access_mask_priv_reg |= _TAMP_PRIVCFG_BKPWPRIV;
				break;
			default:
				panic();
			}
		}
	}

	/*
	 * When TDCID, OP-TEE should be the one to set the CID filtering
	 * configuration. Clearing previous configuration prevents
	 * undesired events during the only legitimate configuration.
	 */
	if (stm32_tamp_dev->pdata.is_tdcid) {
		for (i = 0; i < TAMP_RIF_RESOURCES; i++)
			if (BIT(i) & rif_conf->access_mask[0])
				io_clrbits32(base + _TAMP_CIDCFGR(i),
					     _TAMP_CIDCFGR_CONF_MASK);
	}

	if (rif_conf->sec_conf[0] & _TAMP_SECCFGR_RIF_TAMP_SEC)
		seccfgr |= _TAMP_SECCFGR_TAMPSEC;
	if (rif_conf->sec_conf[0] & _TAMP_SECCFGR_RIF_COUNT_1)
		seccfgr |= _TAMP_SECCFGR_CNT1SEC;
	if (rif_conf->sec_conf[0] & _TAMP_SECCFGR_RIF_COUNT_2)
		seccfgr |= _TAMP_SECCFGR_CNT2SEC;

	if (rif_conf->priv_conf[0] & _TAMP_PRIVCFGR_RIF_TAMP_PRIV)
		privcfgr |= _TAMP_PRIVCFG_TAMPPRIV;
	if (rif_conf->priv_conf[0] & _TAMP_PRIVCFGR_RIF_R1)
		privcfgr |= _TAMP_PRIVCFG_CNT1PRIV | _TAMP_PRIVCFG_BKPRWPRIV;
	if (rif_conf->priv_conf[0] & _TAMP_PRIVCFGR_RIF_R2)
		privcfgr |= _TAMP_PRIVCFG_CNT2PRIV | _TAMP_PRIVCFG_BKPWPRIV;

	/* Security and privilege RIF configuration */
	io_clrsetbits32(base + _TAMP_PRIVCFGR, access_mask_priv_reg, privcfgr);
	io_clrsetbits32(base + _TAMP_SECCFGR, access_mask_sec_reg, seccfgr);

	if (!stm32_tamp_dev->pdata.is_tdcid)
		return;

	for (i = 0; i < TAMP_RIF_RESOURCES; i++) {
		if (!(BIT(i) & rif_conf->access_mask[0]))
			continue;

		io_clrsetbits32(base + _TAMP_CIDCFGR(i),
				_TAMP_CIDCFGR_CONF_MASK,
				rif_conf->cid_confs[i]);
	}
}

static TEE_Result stm32_tamp_apply_bkpr_rif_conf(void)
{
	struct stm32_bkpregs_conf *bkpregs_conf =
			&stm32_tamp_dev->pdata.bkpregs_conf;
	vaddr_t base = get_base();
	unsigned int i = 0;

	if (!bkpregs_conf->rif_offsets)
		panic("No backup register configuration");

	for (i = 0; i < TAMP_RIF_OFFSET_CNT; i++) {
		if (bkpregs_conf->rif_offsets[i] >
		    (stm32_tamp_dev->hwconf1 & _TAMP_HWCFGR1_BKPREG))
			return TEE_ERROR_NOT_SUPPORTED;
	}

	/* Fill the 3 TAMP_BKPRIFRx registers */
	io_clrsetbits32(base + _TAMP_BKPRIFR(1), _TAMP_BKPRIFR_1_MASK,
			bkpregs_conf->rif_offsets[0]);
	io_clrsetbits32(base + _TAMP_BKPRIFR(2), _TAMP_BKPRIFR_2_MASK,
			bkpregs_conf->rif_offsets[1]);
	io_clrsetbits32(base + _TAMP_BKPRIFR(3), _TAMP_BKPRIFR_3_MASK,
			bkpregs_conf->rif_offsets[2] |
			SHIFT_U32(bkpregs_conf->rif_offsets[3],
				  _TAMP_BKPRIFR_ZONE3_RIF2_SHIFT));

	DMSG("Backup registers mapping :");
	DMSG("********START of zone 1********");
	DMSG("Protection Zone 1-RIF1 begins at register: 0");
	DMSG("Protection Zone 1-RIF2 begins at register: %"PRIu32,
	     bkpregs_conf->rif_offsets[0]);
	DMSG("Protection Zone 1-RIF2 ends at register: %"PRIu32,
	     bkpregs_conf->zone1_end ? bkpregs_conf->zone1_end - 1 : 0);
	DMSG("********END of zone 1********");
	DMSG("********START of zone 2********");
	DMSG("Protection Zone 2-RIF1 begins at register: %"PRIu32,
	     bkpregs_conf->zone1_end);
	DMSG("Protection Zone 2-RIF2 begins at register: %"PRIu32,
	     bkpregs_conf->rif_offsets[1]);
	DMSG("Protection Zone 2-RIF2 ends at register: %"PRIu32,
	     bkpregs_conf->rif_offsets[1] > bkpregs_conf->zone1_end ?
	     bkpregs_conf->zone2_end - 1 : 0);
	DMSG("********END of zone 2********");
	DMSG("********START of zone 3********");
	DMSG("Protection Zone 3-RIF1 begins at register: %"PRIu32,
	     bkpregs_conf->zone2_end);
	DMSG("Protection Zone 3-RIF0 begins at register: %"PRIu32,
	     bkpregs_conf->rif_offsets[2]);
	DMSG("Protection Zone 3-RIF2 begins at register: %"PRIu32,
	     bkpregs_conf->rif_offsets[3]);
	DMSG("Protection Zone 3-RIF2 ends at the last register: %"PRIu32,
	     stm32_tamp_dev->hwconf1 & _TAMP_HWCFGR1_BKPREG);
	DMSG("********END of zone 3********");

	return TEE_SUCCESS;
}

static TEE_Result stm32_tamp_set_secure_bkpregs(void)
{
	struct stm32_bkpregs_conf *bkpregs_conf =
		&stm32_tamp_dev->pdata.bkpregs_conf;
	vaddr_t base = get_base();
	uint32_t first_z2 = 0;
	uint32_t first_z3 = 0;

	first_z2 = bkpregs_conf->zone1_end;
	first_z3 = bkpregs_conf->zone2_end;

	if ((first_z2 > (stm32_tamp_dev->hwconf1 & _TAMP_HWCFGR1_BKPREG)) ||
	    (first_z3 > (stm32_tamp_dev->hwconf1 & _TAMP_HWCFGR1_BKPREG)))
		return TEE_ERROR_BAD_PARAMETERS;

	if (stm32_tamp_dev->pdata.compat &&
	    (stm32_tamp_dev->pdata.compat->tags & TAMP_HAS_REGISTER_SECCFGR)) {
		io_clrsetbits32(base + _TAMP_SECCFGR,
				_TAMP_SECCFGR_BKPRWSEC_MASK,
				(first_z2 << _TAMP_SECCFGR_BKPRWSEC_SHIFT) &
				_TAMP_SECCFGR_BKPRWSEC_MASK);

		io_clrsetbits32(base + _TAMP_SECCFGR,
				_TAMP_SECCFGR_BKPWSEC_MASK,
				(first_z3 << _TAMP_SECCFGR_BKPWSEC_SHIFT) &
				_TAMP_SECCFGR_BKPWSEC_MASK);
	} else {
		io_clrsetbits32(base + _TAMP_SMCR,
				_TAMP_SMCR_BKPRWDPROT_MASK,
				(first_z2 << _TAMP_SMCR_BKPRWDPROT_SHIFT) &
				_TAMP_SMCR_BKPRWDPROT_MASK);

		io_clrsetbits32(base + _TAMP_SMCR,
				_TAMP_SMCR_BKPWDPROT_MASK,
				(first_z3 << _TAMP_SMCR_BKPWDPROT_SHIFT) &
				_TAMP_SMCR_BKPWDPROT_MASK);
	}

	return TEE_SUCCESS;
}

static void stm32_tamp_set_secure(uint32_t mode)
{
	vaddr_t base = get_base();

	if (stm32_tamp_dev->pdata.compat &&
	    (stm32_tamp_dev->pdata.compat->tags & TAMP_HAS_REGISTER_SECCFGR)) {
		io_clrsetbits32(base + _TAMP_SECCFGR,
				_TAMP_SECCFGR_BUT_BKP_MASK,
				mode & _TAMP_SECCFGR_BUT_BKP_MASK);
	} else {
		/*
		 * Note: MP15 doesn't use SECCFG register and
		 * inverts the secure bit.
		 */
		if (mode & _TAMP_SECCFGR_TAMPSEC)
			io_clrbits32(base + _TAMP_SMCR, _TAMP_SMCR_DPROT);
		else
			io_setbits32(base + _TAMP_SMCR, _TAMP_SMCR_DPROT);
	}
}

static void stm32_tamp_set_privilege(uint32_t mode)
{
	vaddr_t base = get_base();

	if (stm32_tamp_dev->pdata.compat &&
	    (stm32_tamp_dev->pdata.compat->tags & TAMP_HAS_REGISTER_PRIVCFGR))
		io_clrsetbits32(base + _TAMP_PRIVCFGR, _TAMP_PRIVCFGR_MASK,
				mode & _TAMP_PRIVCFGR_MASK);
}

static void parse_bkpregs_dt_conf(const void *fdt, int node)
{
	struct stm32_tamp_platdata *pdata = &stm32_tamp_dev->pdata;
	unsigned int bkpregs_count = 0;
	const fdt32_t *cuint = NULL;
	int lenp = 0;

	cuint = fdt_getprop(fdt, node, "st,backup-zones", &lenp);
	if (!cuint)
		panic("Missing backup registers configuration");

	/*
	 * When TAMP does not support RIF, the backup registers can
	 * be splited in 3 zones. These zones have specific read/write
	 * access permissions based on the secure status of the accesser.
	 * When RIF is supported, these zones can additionally be splited
	 * in subzones that have CID filtering. Zones/Subzones can be empty and
	 * are contiguous.
	 */
	if (!(pdata->compat->tags & TAMP_HAS_RIF_SUPPORT)) {
		/* 3 zones, 2 offsets to apply */
		if (lenp != sizeof(uint32_t) * TAMP_NB_BKPR_ZONES)
			panic("Incorrect bkpregs configuration");

		pdata->bkpregs_conf.zone1_end = fdt32_to_cpu(cuint[0]);
		bkpregs_count = fdt32_to_cpu(cuint[0]);

		pdata->bkpregs_conf.zone2_end = bkpregs_count +
						fdt32_to_cpu(cuint[1]);
	} else {
		/*
		 * Zone 3
		 * ----------------------|
		 * Protection Zone 3-RIF2|Read non-
		 * ----------------------|secure
		 * Protection Zone 3-RIF0|Write non-
		 * ----------------------|secure
		 * Protection Zone 3-RIF1|
		 * ----------------------|
		 *
		 * Zone 2
		 * ----------------------|
		 * Protection Zone 2-RIF2|Read non-
		 * ----------------------|secure
		 * Protection Zone 2-RIF1|Write secure
		 * ----------------------|
		 *
		 * Zone 1
		 * ----------------------|
		 * Protection Zone 1-RIF2|Read secure
		 * ----------------------|Write secure
		 * Protection Zone 1-RIF1|
		 * ----------------------|
		 *
		 * (BHK => First 8 registers)
		 */
		pdata->bkpregs_conf.rif_offsets = calloc(TAMP_RIF_OFFSET_CNT,
							 sizeof(uint32_t));
		if (!pdata->bkpregs_conf.rif_offsets)
			panic();

		/*
		 * 3 zones with 7 subzones in total(6 offsets):
		 * - 2 zone offsets
		 * - 4 subzones offsets
		 */
		if (lenp != sizeof(uint32_t) *
		    (TAMP_RIF_OFFSET_CNT + TAMP_NB_BKPR_ZONES))
			panic("Incorrect bkpregs configuration");

		/* Backup registers zone 1 */
		pdata->bkpregs_conf.rif_offsets[0] = fdt32_to_cpu(cuint[0]);
		pdata->bkpregs_conf.zone1_end = fdt32_to_cpu(cuint[0]) +
						fdt32_to_cpu(cuint[1]);

		bkpregs_count = pdata->bkpregs_conf.zone1_end;

		/* Backup registers zone 2 */
		pdata->bkpregs_conf.rif_offsets[1] = bkpregs_count +
						     fdt32_to_cpu(cuint[2]);
		pdata->bkpregs_conf.zone2_end = bkpregs_count +
						fdt32_to_cpu(cuint[2]) +
						fdt32_to_cpu(cuint[3]);

		bkpregs_count = pdata->bkpregs_conf.zone2_end;

		/* Backup registers zone 3 */
		pdata->bkpregs_conf.rif_offsets[2] = bkpregs_count +
						     fdt32_to_cpu(cuint[4]);
		pdata->bkpregs_conf.rif_offsets[3] = bkpregs_count +
						      fdt32_to_cpu(cuint[4]) +
						      fdt32_to_cpu(cuint[5]);
	}
}

static void stm32_tamp_set_pins(vaddr_t base, uint32_t mode)
{
	io_setbits32(base + _TAMP_OR, mode);
}

static TEE_Result stm32_tamp_set_seed(vaddr_t base)
{
	uint32_t value = 0;
	int idx = 0;

	for (idx = 0; idx < 4; idx++) {
		uint32_t rnd = 0;

		if (crypto_rng_read(&rnd, sizeof(uint32_t)))
			return TEE_ERROR_BAD_STATE;

		io_write32(base + _TAMP_ATSEEDR, rnd);
	}

	if (IO_READ32_POLL_TIMEOUT(base + _TAMP_ATOR, value,
				   !(value & _TAMP_SEEDF), 0, SEED_TIMEOUT_US))
		return TEE_ERROR_BAD_STATE;

	return TEE_SUCCESS;
}

static TEE_Result is_int_tamp_id_valid(enum stm32_tamp_id id)
{
	if (id - INT_TAMP1 >= _TAMP_HWCFGR1_ITAMP_MAX_ID)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!(stm32_tamp_dev->hwconf1 & _TAMP_HWCFGR1_ITAMP(id)))
		return TEE_ERROR_ITEM_NOT_FOUND;

	return TEE_SUCCESS;
}

static bool is_ext_tamp_id_valid(enum stm32_tamp_id id)
{
	return id - EXT_TAMP1 <=
	       (stm32_tamp_dev->hwconf1 & _TAMP_HWCFGR1_TAMPER) >>
	       _TAMP_HWCFGR1_TAMPER_SHIFT;
}

static enum itr_return stm32_tamp_it_handler(struct itr_handler *h __unused)
{
	struct optee_rtc_time __maybe_unused tamp_ts = { };
	vaddr_t base = get_base();
	uint32_t it = io_read32(base + _TAMP_SR);
	uint32_t int_it = it & _TAMP_SR_ITAMPXF_MASK;
	uint32_t ext_it = it & _TAMP_SR_ETAMPXF_MASK;
	bool ts_enabled = false;
	size_t i = 0;

	if (stm32_rtc_is_timestamp_enabled(&ts_enabled))
		panic();

	if (ts_enabled && it) {
		TEE_Result res = stm32_rtc_get_timestamp(&tamp_ts);

		if (res)
			EMSG("Failed to get RTC timestamp: %"PRIx32, res);
		FMSG("Tamper event occurred at:");
		FMSG("\n \t Date: %"PRIu32"/%"PRIu32"\n \t Time: %"PRIu32":%"PRIu32":%"PRIu32,
		     tamp_ts.tm_mday, tamp_ts.tm_mon, tamp_ts.tm_hour,
		     tamp_ts.tm_min, tamp_ts.tm_sec);
	}

	while (int_it && i < stm32_tamp_dev->pdata.compat->int_tamp_size) {
		struct stm32_tamp_tamper_data int_tamp =
			stm32_tamp_dev->pdata.compat->int_tamp[i];
		int id = int_tamp.id;

		if (int_it & _TAMP_SR_ITAMP(id)) {
			uint32_t ret = 0;

			int_it &= ~_TAMP_SR_ITAMP(id);

			if (int_tamp.func)
				ret = int_tamp.func(id);

			if (ret & TAMP_CB_ACK)
				io_setbits32(base + _TAMP_SCR,
					     _TAMP_SCR_ITAMP(id));

			if (ret & TAMP_CB_RESET)
				do_reset("Internal tamper event detected");
		}
		i++;
	}

	i = 0;
	/* External tamper interrupt */
	while (ext_it && i < stm32_tamp_dev->pdata.compat->ext_tamp_size) {
		struct stm32_tamp_tamper_data ext_tamp =
			stm32_tamp_dev->pdata.compat->ext_tamp[i];
		int id = ext_tamp.id;

		if (ext_it & _TAMP_SR_ETAMP(id)) {
			uint32_t ret = 0;

			ext_it &= ~_TAMP_SR_ETAMP(id);

			if (ext_tamp.func)
				ret = ext_tamp.func(id);

			if (ret & TAMP_CB_ACK)
				io_setbits32(base + _TAMP_SCR,
					     _TAMP_SCR_ETAMP(id));

			if (ret & TAMP_CB_RESET)
				do_reset("External tamper event detected");
		}
		i++;
	}

	return ITRR_HANDLED;
}
DECLARE_KEEP_PAGER(stm32_tamp_it_handler);

static TEE_Result stm32_tamp_set_int_config(struct stm32_tamp_compat *tcompat,
					    uint32_t itamp_index, uint32_t *cr1,
					    uint32_t *cr3, uint32_t *ier)
{
	struct stm32_tamp_tamper_data *tamp_int = NULL;
	enum stm32_tamp_id id = INVALID_TAMP;
	TEE_Result res = TEE_ERROR_GENERIC;

	if (!tcompat)
		return TEE_ERROR_BAD_PARAMETERS;

	tamp_int = &tcompat->int_tamp[itamp_index];
	id = tamp_int->id;

	res = is_int_tamp_id_valid(id);
	if (res == TEE_ERROR_ITEM_NOT_FOUND)
		return TEE_SUCCESS;
	else if (res)
		return res;

	/*
	 * If there is no callback
	 * this tamper is disabled, we reset its configuration.
	 */
	if (!tamp_int->func) {
		*cr1 &= ~_TAMP_CR1_ITAMP(id);
		*ier &= ~_TAMP_IER_ITAMP(id);
		if (tcompat->tags & TAMP_HAS_REGISTER_CR3)
			*cr3 &= ~_TAMP_CR3_ITAMPNOER(id);

		FMSG("INT_TAMP%d disabled", id - INT_TAMP1 + 1);
		return TEE_SUCCESS;
	}

	*cr1 |= _TAMP_CR1_ITAMP(id);
	*ier |= _TAMP_IER_ITAMP(id);

	if (tcompat->tags & TAMP_HAS_REGISTER_CR3) {
		if (tamp_int->mode & TAMP_NOERASE)
			*cr3 |= _TAMP_CR3_ITAMPNOER(id);
		else
			*cr3 &= ~_TAMP_CR3_ITAMPNOER(id);
	}

	DMSG("'%s' internal tamper enabled in %s mode",
	     itamper_name[id - INT_TAMP1],
	     (tamp_int->mode & TAMP_NOERASE) ? "potential" : "confirmed");

	return TEE_SUCCESS;
}

static TEE_Result stm32_tamp_set_ext_config(struct stm32_tamp_compat *tcompat,
					    uint32_t etamp_index, uint32_t *cr1,
					    uint32_t *cr2, uint32_t *atcr1,
					    uint32_t *atcr2, uint32_t *ier)
{
	struct stm32_tamp_tamper_data *tamp_ext = NULL;
	enum stm32_tamp_id id = INVALID_TAMP;

	if (!tcompat)
		return TEE_ERROR_BAD_PARAMETERS;

	tamp_ext = &tcompat->ext_tamp[etamp_index];
	id = tamp_ext->id;

	/* Exit if not a valid TAMP_ID */
	if (!is_ext_tamp_id_valid(id))
		return TEE_ERROR_BAD_PARAMETERS;

	/*
	 * If there is no callback or this TAMPER wasn't defined in DT,
	 * this tamper is disabled, we reset its configuration.
	 */
	if (!tamp_ext->func || !(tamp_ext->mode & TAMP_IN_DT)) {
		*cr1 &= ~_TAMP_CR1_ETAMP(id);
		*cr2 &= ~_TAMP_CR2_ETAMPMSK(id);
		*cr2 &= ~_TAMP_CR2_ETAMPTRG(id);
		*cr2 &= ~_TAMP_CR2_ETAMPNOER(id);
		*ier &= ~_TAMP_IER_ETAMP(id);

		FMSG("EXT_TAMP%d disabled", id - EXT_TAMP1 + 1);
		return TEE_SUCCESS;
	}

	*cr1 |= _TAMP_CR1_ETAMP(id);

	if (tamp_ext->mode & TAMP_TRIG_ON)
		*cr2 |= _TAMP_CR2_ETAMPTRG(id);
	else
		*cr2 &= ~_TAMP_CR2_ETAMPTRG(id);

	if (tamp_ext->mode & TAMP_ACTIVE) {
		*atcr1 |= _TAMP_ATCR1_ETAMPAM(id);

		/* Configure output pin if ATOSHARE is selected */
		if (*atcr1 & _TAMP_ATCR1_ATOSHARE) {
			if (tcompat->tags & TAMP_HAS_REGISTER_ATCR2)
				*atcr2 = (*atcr2 &
					  ~_TAMP_ATCR2_ATOSEL_MASK(id)) |
					 _TAMP_ATCR2_ATOSEL(id,
							    tamp_ext->out_id);
			else
				*atcr1 = (*atcr1 &
					  ~_TAMP_ATCR1_ATOSEL_MASK(id)) |
					 _TAMP_ATCR1_ATOSEL(id,
							    tamp_ext->out_id);
		}
	} else {
		*atcr1 &= ~_TAMP_ATCR1_ETAMPAM(id);
	}

	if (tamp_ext->mode & TAMP_NOERASE)
		*cr2 |= _TAMP_CR2_ETAMPNOER(id);
	else
		*cr2 &= ~_TAMP_CR2_ETAMPNOER(id);

	if (id < _TAMP_CR2_ETAMPMSK_MAX_ID) {
		/*
		 * Only external TAMP 1, 2 and 3 can be masked
		 * and we may want them masked at startup.
		 */
		if (tamp_ext->mode & TAMP_EVT_MASK) {
			/*
			 * ETAMP(id) event generates a trigger event. This
			 * ETAMP(id) is masked and internally cleared by
			 * hardware.
			 * The secrets are not erased.
			 */
			*ier &= ~_TAMP_IER_ETAMP(id);
			*cr2 |= _TAMP_CR2_ETAMPMSK(id);
		} else {
			/*
			 * normal ETAMP interrupt:
			 * ETAMP(id) event generates a trigger event and
			 * TAMP(id) must be cleared by software to allow
			 * next tamper event detection.
			 */
			*ier |= _TAMP_IER_ETAMP(id);
			*cr2 &= ~_TAMP_CR2_ETAMPMSK(id);
		}
	} else {
		/* Other than 1,2,3 external TAMP, we want its interrupt */
		*ier |= _TAMP_IER_ETAMP(id);
	}

	DMSG("EXT_TAMP%d enabled as a %s tamper in %s mode, trig_%s %s",
	     id - EXT_TAMP1 + 1,
	     (tamp_ext->mode & TAMP_ACTIVE) ? "active" : "passive",
	     (tamp_ext->mode & TAMP_NOERASE) ? "potential" : "confirmed",
	     (tamp_ext->mode & TAMP_TRIG_ON) ? "on" : "off",
	     (tamp_ext->mode & TAMP_EVT_MASK) ? " (masked)" : "");

	if (tamp_ext->mode & TAMP_ACTIVE)
		DMSG("   linked with OUT_TAMP%"PRIu32,
		     tamp_ext->out_id - OUT_TAMP1 + 1);

	return TEE_SUCCESS;
}

/*
 * Count number of 1 in bitmask
 * Cannot use __builtin_popcount(): libgcc.a for ARMV7 use hardfloat ABI,
 * but OP-TEE core is compiled with softfloat ABI.
 */
static int popcount(uint32_t bitmask)
{
	int nb = 0;

	while (bitmask) {
		if (bitmask & 1)
			nb++;
		bitmask >>= 1;
	}

	return nb;
}

static void stm32_tamp_set_atper(uint32_t pins_out_bits, uint32_t *atcr1)
{
	uint32_t conf = 0;

	switch (popcount(pins_out_bits)) {
	case 0:
	case 1:
		conf = 0;
		break;
	case 2:
		conf = 1;
		break;
	case 3:
	case 4:
		conf = 2;
		break;
	default:
		conf = 3;
		break;
	}

	*atcr1 |= SHIFT_U32(conf, _TAMP_ATCR1_ATPER_SHIFT) &
		  _TAMP_ATCR1_ATPER_MASK;
}

static TEE_Result stm32_tamp_set_config(void)
{
	TEE_Result ret = TEE_SUCCESS;
	vaddr_t base = get_base();
	uint32_t atcr1 = 0;
	uint32_t atcr2 = 0;
	uint32_t fltcr = 0;
	uint32_t cr1 = 0;
	uint32_t cr2 = 0;
	uint32_t cr3 = 0;
	uint32_t ier = 0;
	size_t i = 0;

	if (!stm32_tamp_dev->pdata.compat ||
	    !stm32_tamp_dev->pdata.compat->int_tamp ||
	    !stm32_tamp_dev->pdata.compat->ext_tamp)
		return TEE_ERROR_BAD_STATE;

	/* Set passive filter configuration */
	fltcr = stm32_tamp_dev->pdata.passive_conf;

	/* Set active mode configuration */
	atcr1 = stm32_tamp_dev->pdata.active_conf & _TAMP_ATCR1_COMMON_MASK;
	stm32_tamp_set_atper(stm32_tamp_dev->pdata.out_pins, &atcr1);

	for (i = 0; i < stm32_tamp_dev->pdata.compat->int_tamp_size; i++) {
		ret = stm32_tamp_set_int_config(stm32_tamp_dev->pdata.compat, i,
						&cr1, &cr3, &ier);
		if (ret)
			return ret;
	}

	for (i = 0; i < stm32_tamp_dev->pdata.compat->ext_tamp_size; i++) {
		ret = stm32_tamp_set_ext_config(stm32_tamp_dev->pdata.compat, i,
						&cr1, &cr2, &atcr1, &atcr2,
						&ier);
		if (ret)
			return ret;
	}

	/*
	 * We apply configuration all in a row:
	 * As for active ext tamper "all the needed tampers must be enabled in
	 * the same write access".
	 */
	io_write32(base + _TAMP_FLTCR, fltcr);
	FMSG("Set passive conf %08"PRIx32, fltcr);

	/* Active configuration applied only if not already done. */
	if (((io_read32(base + _TAMP_ATOR) & _TAMP_INITS) != _TAMP_INITS)) {
		io_write32(base + _TAMP_ATCR1, atcr1);
		FMSG("Set active conf1 %08"PRIx32, atcr1);

		if (stm32_tamp_dev->pdata.compat->tags &
		    TAMP_HAS_REGISTER_ATCR2) {
			io_write32(base + _TAMP_ATCR2, atcr2);
			FMSG("Set active conf2 %08"PRIx32, atcr2);
		}
	}

	io_write32(base + _TAMP_CR1, cr1);
	io_write32(base + _TAMP_CR2, cr2);
	if (stm32_tamp_dev->pdata.compat->tags & TAMP_HAS_REGISTER_CR3)
		io_write32(base + _TAMP_CR3, cr3);

	/* If active tamper we reinit the seed. */
	if (stm32_tamp_dev->pdata.active_conf) {
		if (stm32_tamp_set_seed(base) != TEE_SUCCESS) {
			EMSG("Active tamper: SEED not initialized");
			return TEE_ERROR_BAD_STATE;
		}
	}

	/* Enable interrupts. */
	io_write32(base + _TAMP_IER, ier);

	return TEE_SUCCESS;
}

/*
 * Mask a tamper event detection for a given @id
 * If ETAMP(id) event generates a trigger event, this ETAMP(id) is masked and
 * internally cleared by hardware. The secrets are not erased.
 */
static TEE_Result __maybe_unused stm32_tamp_set_mask(enum stm32_tamp_id id)
{
	vaddr_t base = get_base();

	/* Only EXT_TAMP1, EXT_TAMP2, EXT_TAMP3 can be masked. */
	if (id < EXT_TAMP1 || id > (EXT_TAMP1 + _TAMP_CR2_ETAMPMSK_MAX_ID))
		return TEE_ERROR_BAD_PARAMETERS;

	/* We cannot mask the event if pending. */
	if (io_read32(base + _TAMP_SR) & _TAMP_SR_ETAMP(id))
		return TEE_ERROR_BAD_STATE;

	/* We disable the IT */
	io_clrbits32(base + _TAMP_IER, _TAMP_IER_ETAMP(id));
	/* We mask the event */
	io_setbits32(base + _TAMP_CR2, _TAMP_CR2_ETAMPMSK(id));

	return TEE_SUCCESS;
}

/*
 * Unmask a tamper event detection for a given @id
 * ETAMP(id) event now generates a trigger event and ETAMP(id) must be cleared
 * by software to allow next tamper event detection.
 */
static TEE_Result __maybe_unused stm32_tamp_unset_mask(enum stm32_tamp_id id)
{
	vaddr_t base = get_base();

	/* Only EXT_TAMP1, EXT_TAMP2, EXT_TAMP3 can be masked. */
	if (id < EXT_TAMP1 || id > (EXT_TAMP1 + _TAMP_CR2_ETAMPMSK_MAX_ID))
		return TEE_ERROR_BAD_PARAMETERS;

	/* We unmask the event */
	io_clrbits32(base + _TAMP_CR2, _TAMP_CR2_ETAMPMSK(id));
	/* We enable the IT */
	io_setbits32(base + _TAMP_IER, _TAMP_IER_ETAMP(id));

	return TEE_SUCCESS;
}

/* This will increment the monotonic counter by 1. It cannot roll-over */
static TEE_Result __maybe_unused stm32_tamp_write_mcounter(int cnt_idx)
{
	vaddr_t base = get_base();

	if (cnt_idx < 0 || !stm32_tamp_dev->pdata.compat ||
	    cnt_idx >= stm32_tamp_dev->pdata.compat->nb_monotonic_counter)
		return TEE_ERROR_BAD_PARAMETERS;

	io_write32(base + _TAMP_COUNTR + cnt_idx * sizeof(uint32_t), 1);

	return TEE_SUCCESS;
}

static uint32_t __maybe_unused stm32_tamp_read_mcounter(int cnt_idx)
{
	vaddr_t base = get_base();

	if (cnt_idx < 0 || !stm32_tamp_dev->pdata.compat ||
	    cnt_idx >= stm32_tamp_dev->pdata.compat->nb_monotonic_counter)
		return 0U;

	return io_read32(base + _TAMP_COUNTR + cnt_idx * sizeof(uint32_t));
}

static TEE_Result stm32_tamp_configure_int(struct stm32_tamp_tamper_data *tamp,
					   uint32_t mode,
					   uint32_t (*cb)(int id))
{
	if (mode & TAMP_EVT_MASK)
		return TEE_ERROR_BAD_PARAMETERS;

	tamp->mode |= (mode & TAMP_MODE_MASK);
	tamp->func = cb;

	return TEE_SUCCESS;
}

static TEE_Result stm32_tamp_configure_ext(struct stm32_tamp_tamper_data *tamp,
					   uint32_t mode,
					   uint32_t (*cb)(int id))
{
	enum stm32_tamp_id id = tamp->id;

	if (mode & TAMP_EVT_MASK && !is_ext_tamp_id_valid(id))
		return TEE_ERROR_BAD_PARAMETERS;

	if (!(tamp->mode & TAMP_IN_DT))
		return TEE_ERROR_ITEM_NOT_FOUND;

	tamp->mode |= (mode & TAMP_MODE_MASK);
	tamp->func = cb;

	return TEE_SUCCESS;
}

/*
 * stm32_tamp_activate_tamp: Configure and activate one tamper (internal or
 * external).
 *
 * @id: tamper ID
 * @mode: bitmask from TAMPER modes define:
 *       TAMP_ERASE/TAMP_NOERASE:
 *            TAMP_ERASE: when this tamper event is triggered; secrets are
 *            erased.
 *            TAMP_NOERASE: when this event is triggered; cryptographic
 *            and some secure peripherals are locked until the event is
 *            acknowledged. If the callback confirms the TAMPER, it
 *            can manually erase secrets with stm32_tamp_erase_secrets().
 *       TAMP_NO_EVT_MASK/TAMP_EVT_MASK:
 *            TAMP_NO_EVT_MASK: normal behavior.
 *            TAMP_EVT_MASK: if the event is triggered, the event is masked and
 *            internally cleared by hardware. Secrets are not erased. Only
 *            applicable for some external tampers. This defines only the status
 *            at boot. To change mask while runtime: stm32_tamp_set_mask() and
 *            stm32_tamp_unset_mask() can be used.
 * @cb: function to call when a tamper event is raised (cannot be NULL).
 *      It is called in interrupt context and returns a bitmask defining
 *      the action to take by the driver:
 *           TAMP_CB_RESET: will reset the board.
 *           TAMP_CB_ACK: this specific tamper is acknowledged (in case
 *                        of no-erase tamper, blocked secret are unblocked).
 *
 * return: TEE_ERROR_BAD_PARAMETERS:
 *                   if @id is not a valid tamper ID,
 *                   if @cb is NULL,
 *                   if TAMP_EVT_MASK @mode is set for an unsupported @id.
 *         TEE_ERROR_BAD_STATE
 *                   if driver was not previously initialized.
 *         TEE_ERROR_ITEM_NOT_FOUND
 *                   if the activated external tamper was not previously
 *                   defined in the device tree.
 *         else TEE_SUCCESS.
 */
static TEE_Result stm32_tamp_activate_tamp(enum stm32_tamp_id id, uint32_t mode,
					   uint32_t (*cb)(int id))
{
	struct stm32_tamp_tamper_data *tamp_conf = NULL;
	size_t i = 0;

	if (!stm32_tamp_dev->pdata.compat)
		return TEE_ERROR_BAD_STATE;

	assert(is_unpaged(cb));

	if (!cb)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Find internal Tamp struct */
	for (i = 0; i < stm32_tamp_dev->pdata.compat->int_tamp_size; i++) {
		if (stm32_tamp_dev->pdata.compat->int_tamp[i].id == id) {
			tamp_conf = &stm32_tamp_dev->pdata.compat->int_tamp[i];
			return stm32_tamp_configure_int(tamp_conf, mode, cb);
		}
	}

	/* Find external Tamp struct */
	for (i = 0; i < stm32_tamp_dev->pdata.compat->ext_tamp_size; i++) {
		if (stm32_tamp_dev->pdata.compat->ext_tamp[i].id == id) {
			tamp_conf = &stm32_tamp_dev->pdata.compat->ext_tamp[i];
			return stm32_tamp_configure_ext(tamp_conf, mode, cb);
		}
	}

	EMSG("Did not find existing tamper for ID:%d", id);

	return TEE_ERROR_BAD_PARAMETERS;
}

static bool __maybe_unused stm32_tamp_are_secrets_blocked(void)
{
	if (stm32_tamp_dev->pdata.compat &&
	    (stm32_tamp_dev->pdata.compat->tags & TAMP_HAS_CR2_SECRET_STATUS)) {
		vaddr_t base = get_base();

		return ((io_read32(base + _TAMP_CR2) & _TAMP_CR2_BKBLOCK) ||
			io_read32(base + _TAMP_SR));
	} else {
		return false;
	}
}

static void __maybe_unused stm32_tamp_block_secrets(void)
{
	vaddr_t base = get_base();

	if (stm32_tamp_dev->pdata.compat &&
	    (stm32_tamp_dev->pdata.compat->tags & TAMP_HAS_CR2_SECRET_STATUS))
		io_setbits32(base + _TAMP_CR2, _TAMP_CR2_BKBLOCK);
}

static void __maybe_unused stm32_tamp_unblock_secrets(void)
{
	vaddr_t base = get_base();

	if (stm32_tamp_dev->pdata.compat &&
	    (stm32_tamp_dev->pdata.compat->tags & TAMP_HAS_CR2_SECRET_STATUS))
		io_clrbits32(base + _TAMP_CR2, _TAMP_CR2_BKBLOCK);
}

static void __maybe_unused stm32_tamp_erase_secrets(void)
{
	vaddr_t base = get_base();

	if (stm32_tamp_dev->pdata.compat &&
	    (stm32_tamp_dev->pdata.compat->tags & TAMP_HAS_CR2_SECRET_STATUS))
		io_setbits32(base + _TAMP_CR2, _TAMP_CR2_BKERASE);
}

static void __maybe_unused stm32_tamp_lock_boot_hardware_key(void)
{
	vaddr_t base = get_base();

	if (stm32_tamp_dev->pdata.compat &&
	    (stm32_tamp_dev->pdata.compat->tags & TAMP_HAS_REGISTER_SECCFGR))
		io_setbits32(base + _TAMP_SECCFGR, _TAMP_SECCFGR_BHKLOCK);
}

static void stm32_tamp_configure_pin(uint32_t id, struct gpio *gpio, bool out,
				     struct stm32_tamp_platdata *pdata)
{
	struct stm32_tamp_compat *compat = pdata->compat;
	unsigned int bank = stm32_gpio_chip_bank_id(gpio->chip);
	unsigned int pin = gpio->pin;
	size_t i = 0;

	if (!compat)
		return;

	/* Configure option registers */
	for (i = 0; i < compat->pin_map_size; i++) {
		if (id == compat->pin_map[i].id &&
		    bank == compat->pin_map[i].bank &&
		    pin == compat->pin_map[i].pin &&
		    out == compat->pin_map[i].out) {
			pdata->pins_conf |= compat->pin_map[i].conf;
			break;
		}
	}
}

static TEE_Result
stm32_tamp_configure_pin_from_dt(const void *fdt, int node,
				 struct stm32_tamp_platdata *pdata,
				 uint32_t ext_tamp_id, uint32_t out_tamp_id)
{
	enum stm32_tamp_out_id out_id = INVALID_OUT_TAMP;
	struct stm32_tamp_tamper_data *tamp_ext = NULL;
	enum stm32_tamp_id id = INVALID_TAMP;
	TEE_Result res = TEE_SUCCESS;
	struct gpio *gpio_out = NULL;
	struct gpio *gpio_ext = NULL;
	bool active = false;
	unsigned int i = 0;

	/*
	 * First GPIO in the tamper-gpios property is required and refers to the
	 * EXT_TAMP control. Second GPIO in the tamper-gpios property is
	 * optional and, if defined, refers to the OUT_TAMP control.
	 * If only one GPIO is defined, the tamper control is a passive tamper.
	 * Else, it is an active tamper.
	 */
	res = gpio_dt_cfg_by_index(fdt, node, 1, "tamper", GPIO_IN, &gpio_out);
	if (res && res != TEE_ERROR_ITEM_NOT_FOUND)
		return res;

	if (res != TEE_ERROR_ITEM_NOT_FOUND) {
		active = true;
		out_id = OUT_TAMP1 + out_tamp_id - 1;
		if (out_tamp_id > pdata->compat->ext_tamp_size) {
			gpio_put(gpio_out);
			return TEE_ERROR_BAD_PARAMETERS;
		}

		stm32_tamp_configure_pin(out_id, gpio_out, true, pdata);
	}

	res = gpio_dt_cfg_by_index(fdt, node, 0, "tamper", GPIO_IN, &gpio_ext);
	if (res) {
		gpio_put(gpio_out);
		return res;
	}

	/* We now configure first pin */
	id = ext_tamp_id + EXT_TAMP1 - 1;

	/* Find external TAMP struct */
	for (i = 0; i < pdata->compat->ext_tamp_size; i++) {
		if (pdata->compat->ext_tamp[i].id == id) {
			tamp_ext = &pdata->compat->ext_tamp[i];
			break;
		}
	}

	if (!tamp_ext) {
		gpio_put(gpio_out);
		gpio_put(gpio_ext);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (active) {
		tamp_ext->mode |= TAMP_ACTIVE;
		tamp_ext->out_id = out_id;
		pdata->out_pins |= BIT(tamp_ext->out_id - OUT_TAMP1);

		if (out_id - OUT_TAMP1 != id - EXT_TAMP1)
			pdata->active_conf |= _TAMP_ATCR1_ATOSHARE;
	} else {
		if (fdt_getprop(fdt, node, "st,trig-on", NULL))
			tamp_ext->mode |= TAMP_TRIG_ON;
	}

	tamp_ext->mode |= TAMP_IN_DT;

	stm32_tamp_configure_pin(id, gpio_ext, false, pdata);

	return TEE_SUCCESS;
}

static TEE_Result
stm32_tamp_parse_passive_conf(const void *fdt, int node,
			      struct stm32_tamp_platdata *pdata)
{
	const fdt32_t *cuint = NULL;
	uint32_t precharge = 0;
	uint32_t nb_sample = 0;
	uint32_t clk_div = 32768;
	uint32_t conf = 0;

	cuint = fdt_getprop(fdt, node, "st,tamp-passive-precharge", NULL);
	if (cuint)
		precharge = fdt32_to_cpu(*cuint);

	cuint = fdt_getprop(fdt, node, "st,tamp-passive-nb-sample", NULL);
	if (cuint)
		nb_sample = fdt32_to_cpu(*cuint);

	cuint = fdt_getprop(fdt, node, "st,tamp-passive-sample-clk-div", NULL);
	if (cuint)
		clk_div = fdt32_to_cpu(*cuint);

	DMSG("Passive conf from dt: precharge=%"PRIu32", nb_sample=%"PRIu32
	     ", clk_div=%"PRIu32, precharge, nb_sample, clk_div);

	switch (precharge) {
	case 0:
		/* No precharge, => we disable the pull-up */
		conf |= _TAMP_FLTCR_TAMPPUDIS;
		break;
	case 1:
		/* Precharge for one cycle value stay 0 */
		break;
	case 2:
		/* Precharge passive pin 2 cycles */
		conf |= SHIFT_U32(1, _TAMP_FLTCR_TAMPPRCH_SHIFT);
		break;
	case 4:
		/* Precharge passive pin 4 cycles */
		conf |= SHIFT_U32(2, _TAMP_FLTCR_TAMPPRCH_SHIFT);
		break;
	case 8:
		/* Precharge passive pin 8 cycles */
		conf |= SHIFT_U32(3, _TAMP_FLTCR_TAMPPRCH_SHIFT);
		break;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}

	switch (nb_sample) {
	case 0:
		/* Activation on edge, no pull-up: value stay 0 */
		break;
	case 2:
		/*
		 * Tamper event is activated after 2 consecutive samples at
		 * active level.
		 */
		conf |= SHIFT_U32(1, _TAMP_FLTCR_TAMPFLT_SHIFT);
		break;
	case 4:
		/*
		 * Tamper event is activated after 4 consecutive samples at
		 * active level.
		 */
		conf |= SHIFT_U32(2, _TAMP_FLTCR_TAMPFLT_SHIFT);
		break;
	case 8:
		/*
		 * Tamper event is activated after 8 consecutive samples at
		 * active level.
		 */
		conf |= SHIFT_U32(3, _TAMP_FLTCR_TAMPFLT_SHIFT);
		break;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}

	switch (clk_div) {
	case 32768:
		/* RTCCLK / 32768 (1 Hz when RTCCLK = 32768 Hz): stay 0 */
		break;
	case 16384:
		/* RTCCLK / 16384 (2 Hz when RTCCLK = 32768 Hz) */
		conf |= SHIFT_U32(1, _TAMP_FLTCR_TAMPFREQ_SHIFT);
		break;
	case 8192:
		/* RTCCLK / 8192  (4 Hz when RTCCLK = 32768 Hz) */
		conf |= SHIFT_U32(2, _TAMP_FLTCR_TAMPFREQ_SHIFT);
		break;
	case 4096:
		/* RTCCLK / 4096  (8 Hz when RTCCLK = 32768 Hz) */
		conf |= SHIFT_U32(3, _TAMP_FLTCR_TAMPFREQ_SHIFT);
		break;
	case 2048:
		/* RTCCLK / 2048  (16 Hz when RTCCLK = 32768 Hz) */
		conf |= SHIFT_U32(4, _TAMP_FLTCR_TAMPFREQ_SHIFT);
		break;
	case 1024:
		/* RTCCLK / 1024  (32 Hz when RTCCLK = 32768 Hz) */
		conf |= SHIFT_U32(5, _TAMP_FLTCR_TAMPFREQ_SHIFT);
		break;
	case 512:
		/* RTCCLK / 512   (64 Hz when RTCCLK = 32768 Hz) */
		conf |= SHIFT_U32(6, _TAMP_FLTCR_TAMPFREQ_SHIFT);
		break;
	case 256:
		/* RTCCLK / 256   (128 Hz when RTCCLK = 32768 Hz) */
		conf |= SHIFT_U32(7, _TAMP_FLTCR_TAMPFREQ_SHIFT);
		break;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}

	pdata->passive_conf = conf;

	return TEE_SUCCESS;
}

static uint32_t stm32_tamp_itamper_action(int id)
{
	const char __maybe_unused *tamp_name = NULL;

	if (id >= 0 && ((size_t)id < ARRAY_SIZE(itamper_name)))
		tamp_name = itamper_name[id];

	MSG("Internal tamper event %u (%s) occurred", id - INT_TAMP1 + 1,
	    tamp_name);

	return TAMP_CB_ACK_AND_RESET;
}
DECLARE_KEEP_PAGER(stm32_tamp_itamper_action);

static uint32_t stm32_tamp_etamper_action(int id __maybe_unused)
{
	MSG("External tamper %u occurs", id - EXT_TAMP1 + 1);

	return TAMP_CB_ACK_AND_RESET;
}
DECLARE_KEEP_PAGER(stm32_tamp_etamper_action);

static TEE_Result stm32_configure_tamp(const void *fdt, int node)
{
	const fdt32_t *internal_tampers = 0;
	uint32_t i_tampers[EXT_TAMP1 * 2] = { };
	int subnode = -FDT_ERR_NOTFOUND;
	TEE_Result res = TEE_SUCCESS;
	int retval = 0;
	int len = 0;
	int i = 0;

	/* Internal tampers configuration */
	internal_tampers = fdt_getprop(fdt, node, "st,tamp-internal-tampers",
				       &len);
	if (len == -FDT_ERR_NOTFOUND)
		goto skip_int_tamp;

	if ((internal_tampers && len % (2 * sizeof(uint32_t))) ||
	    !internal_tampers || len / sizeof(uint32_t) > EXT_TAMP1 * 2)
		return TEE_ERROR_BAD_PARAMETERS;

	retval = fdt_read_uint32_array(fdt, node, "st,tamp-internal-tampers",
				       i_tampers, len / sizeof(uint32_t));
	if (retval && retval != -FDT_ERR_NOTFOUND)
		return TEE_ERROR_BAD_PARAMETERS;

	len = len / sizeof(uint32_t);
	for (i = 0; i < len; i += 2) {
		uint32_t i_tamper_id = i_tampers[i] - 1;
		uint32_t i_tamper_mode = i_tampers[i + 1];

		res = stm32_tamp_activate_tamp(i_tamper_id, i_tamper_mode,
					       stm32_tamp_itamper_action);
		if (res)
			return res;
	}

skip_int_tamp:
	fdt_for_each_subnode(subnode, fdt, node) {
		unsigned int ext_tamp_id = 0;
		unsigned int out_tamp_id = 0;
		const fdt32_t *cuint = 0;
		unsigned int mode = 0;
		int lenp = 0;

		if (!fdt_getprop(fdt, subnode, "tamper-gpios", NULL) ||
		    fdt_get_status(fdt, subnode) == DT_STATUS_DISABLED)
			continue;

		cuint = fdt_getprop(fdt, subnode, "st,tamp-mode", NULL);
		if (!cuint)
			return TEE_ERROR_BAD_PARAMETERS;

		mode = fdt32_to_cpu(*cuint);

		cuint = fdt_getprop(fdt, subnode, "st,tamp-id", &lenp);
		if (!cuint)
			return TEE_ERROR_BAD_PARAMETERS;

		ext_tamp_id = fdt32_to_cpu(*cuint);
		if (lenp > (int)sizeof(uint32_t))
			out_tamp_id = fdt32_to_cpu(*(cuint + 1));

		res = stm32_tamp_configure_pin_from_dt(fdt, subnode,
						       &stm32_tamp_dev->pdata,
						       ext_tamp_id,
						       out_tamp_id);
		if (res)
			return res;

		res = stm32_tamp_activate_tamp(EXT_TAMP1 + ext_tamp_id - 1,
					       mode, stm32_tamp_etamper_action);
		if (res)
			return res;
	}

	if (stm32_tamp_set_config())
		panic();

	/* Enable timestamp for tamper */
	if (stm32_rtc_set_tamper_timestamp())
		panic();

	return TEE_SUCCESS;
}

static TEE_Result
stm32_tamp_parse_active_conf(const void *fdt, int node,
			     struct stm32_tamp_platdata *pdata)
{
	const fdt32_t *cuint = NULL;
	uint32_t clk_div = 1;
	uint32_t conf = 0;

	cuint = fdt_getprop(fdt, node, "st,tamp-active-filter", NULL);
	if (cuint)
		conf |= _TAMP_ATCR1_FLTEN;

	/*
	 * Here we will select a divisor for the RTCCLK.
	 * Note that RTCCLK is also divided by (RTC_PRER_PREDIV_A - 1).
	 */
	cuint = fdt_getprop(fdt, node, "st,tamp-active-clk-div", NULL);
	if (cuint)
		clk_div = fdt32_to_cpu(*cuint);

	DMSG("Active conf from dt: %s clk_div=%"PRIu32,
	     (conf & _TAMP_ATCR1_FLTEN) ? "filter" : "no filter", clk_div);

	switch (clk_div) {
	case 1:
		/* RTCCLK / 32768 (1 Hz when RTCCLK = 32768 Hz): stay 0 */
		break;
	case 2:
		/* RTCCLK / 16384 (2 Hz when RTCCLK = 32768 Hz) */
		conf |= SHIFT_U32(1, _TAMP_ATCR1_ATCKSEL_SHIFT);
		break;
	case 4:
		/* RTCCLK / 8192  (4 Hz when RTCCLK = 32768 Hz) */
		conf |= SHIFT_U32(2, _TAMP_ATCR1_ATCKSEL_SHIFT);
		break;
	case 8:
		/* RTCCLK / 4096  (8 Hz when RTCCLK = 32768 Hz) */
		conf |= SHIFT_U32(3, _TAMP_ATCR1_ATCKSEL_SHIFT);
		break;
	case 16:
		/* RTCCLK / 2048  (16 Hz when RTCCLK = 32768 Hz) */
		conf |= SHIFT_U32(4, _TAMP_ATCR1_ATCKSEL_SHIFT);
		break;
	case 32:
		/* RTCCLK / 1024  (32 Hz when RTCCLK = 32768 Hz) */
		conf |= SHIFT_U32(5, _TAMP_ATCR1_ATCKSEL_SHIFT);
		break;
	case 64:
		/* RTCCLK / 512   (64 Hz when RTCCLK = 32768 Hz) */
		conf |= SHIFT_U32(6, _TAMP_ATCR1_ATCKSEL_SHIFT);
		break;
	case 128:
		/* RTCCLK / 256   (128 Hz when RTCCLK = 32768 Hz) */
		conf |= SHIFT_U32(7, _TAMP_ATCR1_ATCKSEL_SHIFT);
		break;
	case 2048:
		if (pdata->compat &&
		    (pdata->compat->tags & TAMP_SIZE_ATCR1_ATCKSEL_IS_4)) {
			/*
			 * RTCCLK/2048 when (PREDIV_A+1) = 128 and (PREDIV_S+1)
			 * is a multiple of 16.
			 */
			conf |=  SHIFT_U32(11, _TAMP_ATCR1_ATCKSEL_SHIFT);
			break;
		}

		return TEE_ERROR_BAD_PARAMETERS;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}

	pdata->active_conf = conf;

	return TEE_SUCCESS;
}

static TEE_Result stm32_tamp_parse_fdt(const void *fdt, int node,
				       const void *compat)
{
	struct stm32_tamp_platdata *pdata = &stm32_tamp_dev->pdata;
	TEE_Result res = TEE_ERROR_GENERIC;
	size_t reg_size = 0;

	pdata->compat = (struct stm32_tamp_compat *)compat;

	if (stm32_tamp_dev->pdata.compat->tags & TAMP_HAS_RIF_SUPPORT) {
		res = stm32_rifsc_check_tdcid(&pdata->is_tdcid);
		if (res)
			return res;
	}

	if (fdt_reg_info(fdt, node, &pdata->base.pa, &reg_size))
		panic();

	io_pa_or_va_secure(&pdata->base, reg_size);
	assert(pdata->base.va);

	res = clk_dt_get_by_index(fdt, node, 0, &pdata->clock);
	if (res)
		return res;

	res = stm32_tamp_parse_passive_conf(fdt, node, pdata);
	if (res)
		return res;

	res = stm32_tamp_parse_active_conf(fdt, node, pdata);
	if (res)
		return res;

	if (fdt_getprop(fdt, node, "wakeup-source", NULL))
		pdata->is_wakeup_source = true;

	parse_bkpregs_dt_conf(fdt, node);

	if (pdata->compat->tags & TAMP_HAS_RIF_SUPPORT) {
		const fdt32_t *cuint = NULL;
		unsigned int i = 0;
		int lenp = 0;

		cuint = fdt_getprop(fdt, node, "st,protreg", &lenp);
		if (!cuint) {
			DMSG("No RIF configuration available");
			return TEE_SUCCESS;
		}

		pdata->conf_data = calloc(1, sizeof(*pdata->conf_data));
		if (!pdata->conf_data)
			panic();

		pdata->nb_rif_resources = (unsigned int)(lenp /
							 sizeof(uint32_t));
		assert(pdata->nb_rif_resources <= TAMP_RIF_RESOURCES);

		pdata->conf_data->cid_confs = calloc(TAMP_RIF_RESOURCES,
						     sizeof(uint32_t));
		pdata->conf_data->sec_conf = calloc(1, sizeof(uint32_t));
		pdata->conf_data->priv_conf = calloc(1, sizeof(uint32_t));
		pdata->conf_data->access_mask = calloc(1, sizeof(uint32_t));
		if (!pdata->conf_data->cid_confs ||
		    !pdata->conf_data->sec_conf ||
		    !pdata->conf_data->priv_conf ||
		    !pdata->conf_data->access_mask)
			panic("Not enough memory capacity for TAMP RIF config");

		for (i = 0; i < pdata->nb_rif_resources; i++)
			stm32_rif_parse_cfg(fdt32_to_cpu(cuint[i]),
					    pdata->conf_data,
					    TAMP_RIF_RESOURCES);
	}

	return TEE_SUCCESS;
}

static TEE_Result stm32_tamp_probe(const void *fdt, int node,
				   const void *compat_data)
{
	size_t it_num = DT_INFO_INVALID_INTERRUPT;
	uint32_t __maybe_unused revision = 0;
	struct itr_chip *chip = NULL;
	TEE_Result res = TEE_SUCCESS;
	vaddr_t base = 0;

	/* Manage dependency on RNG driver */
	res = dt_driver_get_crypto();
	if (res)
		return res;

	/* Manage dependency on RTC driver */
	res = stm32_rtc_driver_is_initialized();
	if (res)
		return res;

	res = interrupt_dt_get_by_index(fdt, node, 0, &chip, &it_num);
	if (res)
		return res;

	stm32_tamp_dev = calloc(1, sizeof(*stm32_tamp_dev));
	if (!stm32_tamp_dev)
		return TEE_ERROR_OUT_OF_MEMORY;

	res = stm32_tamp_parse_fdt(fdt, node, compat_data);
	if (res)
		goto err;

	if (clk_enable(stm32_tamp_dev->pdata.clock))
		panic();

	base = get_base();

	stm32_tamp_dev->hwconf1 = io_read32(base + _TAMP_HWCFGR1);
	stm32_tamp_dev->hwconf2 = io_read32(base + _TAMP_HWCFGR2);

	revision = io_read32(base + _TAMP_VERR);
	FMSG("STM32 TAMPER V%"PRIx32".%"PRIu32,
	     (revision & _TAMP_VERR_MAJREV) >> 4, revision & _TAMP_VERR_MINREV);

	if (!(stm32_tamp_dev->hwconf2 & _TAMP_HWCFGR2_TZ)) {
		EMSG("TAMP doesn't support TrustZone");
		res = TEE_ERROR_NOT_SUPPORTED;
		goto err_clk;
	}

	if (stm32_tamp_dev->pdata.compat->tags & TAMP_HAS_RIF_SUPPORT) {
		apply_rif_config();

		if (stm32_tamp_dev->pdata.is_tdcid) {
			res = stm32_tamp_apply_bkpr_rif_conf();
			if (res)
				goto err_clk;
		}
	} else {
		/*
		 * Enforce secure only access to protected TAMP registers.
		 * Allow non-secure access to monotonic counter.
		 */
		stm32_tamp_set_secure(_TAMP_SECCFGR_TAMPSEC);

		/*
		 * Enforce privilege only access to TAMP registers, backup
		 * registers and monotonic counter.
		 */
		stm32_tamp_set_privilege(_TAMP_PRIVCFG_TAMPPRIV |
					 _TAMP_PRIVCFG_BKPRWPRIV |
					 _TAMP_PRIVCFG_BKPWPRIV);
	}

	if (!(stm32_tamp_dev->pdata.compat->tags & TAMP_HAS_RIF_SUPPORT) ||
	    stm32_tamp_dev->pdata.is_tdcid) {
		res = stm32_tamp_set_secure_bkpregs();
		if (res)
			goto err_clk;
	}

	res = interrupt_create_handler(chip, it_num, stm32_tamp_it_handler,
				       NULL, ITRF_TRIGGER_LEVEL,
				       &stm32_tamp_dev->pdata.itr);
	if (res)
		goto err_clk;

	if (stm32_tamp_dev->pdata.is_wakeup_source &&
	    interrupt_can_set_wake(chip)) {
		interrupt_set_wake(chip, it_num, true);
		DMSG("Tamper event wakeup capability enabled");
	}

	res = stm32_configure_tamp(fdt, node);
	if (res)
		goto err_clk;

	stm32_tamp_set_pins(base, stm32_tamp_dev->pdata.pins_conf);

	interrupt_enable(chip, it_num);

	return TEE_SUCCESS;

err_clk:
	clk_disable(stm32_tamp_dev->pdata.clock);
err:
	if (stm32_tamp_dev->pdata.conf_data) {
		free(stm32_tamp_dev->pdata.conf_data->cid_confs);
		free(stm32_tamp_dev->pdata.conf_data->sec_conf);
		free(stm32_tamp_dev->pdata.conf_data->priv_conf);
		free(stm32_tamp_dev->pdata.conf_data->access_mask);
		free(stm32_tamp_dev->pdata.conf_data);
	}

	if (stm32_tamp_dev->pdata.itr) {
		interrupt_disable(chip, it_num);
		interrupt_remove_free_handler(stm32_tamp_dev->pdata.itr);
	}

	free(stm32_tamp_dev->pdata.bkpregs_conf.rif_offsets);
	free(stm32_tamp_dev);

	return res;
}

static const struct stm32_tamp_compat mp13_compat = {
	.nb_monotonic_counter = 2,
	.tags = TAMP_HAS_REGISTER_SECCFGR | TAMP_HAS_REGISTER_PRIVCFGR |
		TAMP_HAS_REGISTER_ERCFGR | TAMP_HAS_REGISTER_CR3 |
		TAMP_HAS_REGISTER_ATCR2 | TAMP_HAS_CR2_SECRET_STATUS |
		TAMP_SIZE_ATCR1_ATCKSEL_IS_4,
#if defined(CFG_STM32MP13)
	.int_tamp = int_tamp_mp13,
	.int_tamp_size = ARRAY_SIZE(int_tamp_mp13),
	.ext_tamp = ext_tamp_mp13,
	.ext_tamp_size = ARRAY_SIZE(ext_tamp_mp13),
	.pin_map = pin_map_mp13,
	.pin_map_size = ARRAY_SIZE(pin_map_mp13),
#endif
};

static const struct stm32_tamp_compat mp15_compat = {
	.nb_monotonic_counter = 1,
	.tags = 0,
#if defined(CFG_STM32MP15)
	.int_tamp = int_tamp_mp15,
	.int_tamp_size = ARRAY_SIZE(int_tamp_mp15),
	.ext_tamp = ext_tamp_mp15,
	.ext_tamp_size = ARRAY_SIZE(ext_tamp_mp15),
	.pin_map = pin_map_mp15,
	.pin_map_size = ARRAY_SIZE(pin_map_mp15),
#endif
};

static const struct stm32_tamp_compat mp21_compat = {
		.nb_monotonic_counter = 2,
		.tags = TAMP_HAS_REGISTER_SECCFGR |
			TAMP_HAS_REGISTER_PRIVCFGR |
			TAMP_HAS_RIF_SUPPORT |
			TAMP_HAS_REGISTER_ERCFGR |
			TAMP_HAS_REGISTER_CR3 |
			TAMP_HAS_REGISTER_ATCR2 |
			TAMP_HAS_CR2_SECRET_STATUS |
			TAMP_SIZE_ATCR1_ATCKSEL_IS_4,
#if defined(CFG_STM32MP21)
		.int_tamp = int_tamp_mp21,
		.int_tamp_size = ARRAY_SIZE(int_tamp_mp21),
		.ext_tamp = ext_tamp_mp21,
		.ext_tamp_size = ARRAY_SIZE(ext_tamp_mp21),
		.pin_map = pin_map_mp21,
		.pin_map_size = ARRAY_SIZE(pin_map_mp21),
#endif
};

static const struct stm32_tamp_compat mp25_compat = {
	.nb_monotonic_counter = 2,
	.tags = TAMP_HAS_REGISTER_SECCFGR | TAMP_HAS_REGISTER_PRIVCFGR |
		TAMP_HAS_RIF_SUPPORT | TAMP_HAS_REGISTER_ERCFGR |
		TAMP_HAS_REGISTER_CR3 |	TAMP_HAS_REGISTER_ATCR2 |
		TAMP_HAS_CR2_SECRET_STATUS | TAMP_SIZE_ATCR1_ATCKSEL_IS_4,
#if defined(CFG_STM32MP25)
	.int_tamp = int_tamp_mp25,
	.int_tamp_size = ARRAY_SIZE(int_tamp_mp25),
	.ext_tamp = ext_tamp_mp25,
	.ext_tamp_size = ARRAY_SIZE(ext_tamp_mp25),
	.pin_map = pin_map_mp25,
	.pin_map_size = ARRAY_SIZE(pin_map_mp25),
#endif
};

static const struct stm32_tamp_compat mp23_compat = {
		.nb_monotonic_counter = 2,
		.tags = TAMP_HAS_REGISTER_SECCFGR |
			TAMP_HAS_REGISTER_PRIVCFGR |
			TAMP_HAS_RIF_SUPPORT |
			TAMP_HAS_REGISTER_ERCFGR |
			TAMP_HAS_REGISTER_CR3 |
			TAMP_HAS_REGISTER_ATCR2 |
			TAMP_HAS_CR2_SECRET_STATUS,
#if defined(CFG_STM32MP23)
		.int_tamp = int_tamp_mp25,
		.int_tamp_size = ARRAY_SIZE(int_tamp_mp25),
		.ext_tamp = ext_tamp_mp23,
		.ext_tamp_size = ARRAY_SIZE(ext_tamp_mp23),
		.pin_map = pin_map_mp25,
		.pin_map_size = ARRAY_SIZE(pin_map_mp25),
#endif
};

static const struct dt_device_match stm32_tamp_match_table[] = {
	{ .compatible = "st,stm32mp25-tamp", .compat_data = &mp25_compat },
	{ .compatible = "st,stm32mp23-tamp", .compat_data = &mp23_compat },
	{ .compatible = "st,stm32mp21-tamp", .compat_data = &mp21_compat },
	{ .compatible = "st,stm32mp13-tamp", .compat_data = &mp13_compat },
	{ .compatible = "st,stm32-tamp", .compat_data = &mp15_compat },
	{ }
};

DEFINE_DT_DRIVER(stm32_tamp_dt_driver) = {
	.name = "stm32-tamp",
	.match_table = stm32_tamp_match_table,
	.probe = stm32_tamp_probe,
};
