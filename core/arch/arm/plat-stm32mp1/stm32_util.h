/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2018-2022, STMicroelectronics
 */

#ifndef __STM32_UTIL_H__
#define __STM32_UTIL_H__

#include <assert.h>
#include <drivers/clk.h>
#include <drivers/pinctrl.h>
#include <drivers/stm32_bsec.h>
#include <kernel/panic.h>
#include <stdint.h>
#include <tee_api_types.h>
#include <types_ext.h>

/* Backup registers and RAM utils */
vaddr_t stm32mp_bkpreg(unsigned int idx);

/* Platform util for the RCC drivers */
vaddr_t stm32_rcc_base(void);

/* Platform util for the GIC */
vaddr_t get_gicd_base(void);

/* Platform util for PMIC support */
bool stm32mp_with_pmic(void);

/* Power management service */
#ifdef CFG_PSCI_ARM32
void stm32mp_register_online_cpu(void);
#else
static inline void stm32mp_register_online_cpu(void)
{
}
#endif

/*
 * Generic spinlock function that bypass spinlock if MMU is disabled or
 * lock is NULL.
 */
uint32_t may_spin_lock(unsigned int *lock);
void may_spin_unlock(unsigned int *lock, uint32_t exceptions);

/* Helper from platform RCC clock driver */
struct clk *stm32mp_rcc_clock_id_to_clk(unsigned long clock_id);

#ifdef CFG_STM32MP1_SHARED_RESOURCES
/* Return true if @clock_id is shared by secure and non-secure worlds */
bool stm32mp_nsec_can_access_clock(unsigned long clock_id);
#else /* CFG_STM32MP1_SHARED_RESOURCES */
static inline bool stm32mp_nsec_can_access_clock(unsigned long clock_id
						 __unused)
{
	return true;
}
#endif /* CFG_STM32MP1_SHARED_RESOURCES */

extern const struct clk_ops stm32mp1_clk_ops;

#if defined(CFG_STPMIC1)
/* Return true if non-secure world can manipulate regulator @pmic_regu_name */
bool stm32mp_nsec_can_access_pmic_regu(const char *pmic_regu_name);
#else
static inline bool stm32mp_nsec_can_access_pmic_regu(const char *name __unused)
{
	return false;
}
#endif

#ifdef CFG_STM32MP1_SHARED_RESOURCES
/* Return true if and only if @reset_id relates to a non-secure peripheral */
bool stm32mp_nsec_can_access_reset(unsigned int reset_id);
#else /* CFG_STM32MP1_SHARED_RESOURCES */
static inline bool stm32mp_nsec_can_access_reset(unsigned int reset_id __unused)
{
	return true;
}
#endif /* CFG_STM32MP1_SHARED_RESOURCES */

/* Return rstctrl instance related to RCC reset controller DT binding ID */
struct rstctrl *stm32mp_rcc_reset_id_to_rstctrl(unsigned int binding_id);

/*
 * Structure and API function for BSEC driver to get some platform data.
 *
 * @base: BSEC interface registers physical base address
 * @upper_start: Base ID for the BSEC upper words in the platform
 * @max_id: Max value for BSEC word ID for the platform
 */
struct stm32_bsec_static_cfg {
	paddr_t base;
	unsigned int upper_start;
	unsigned int max_id;
};

void stm32mp_get_bsec_static_cfg(struct stm32_bsec_static_cfg *cfg);

/*
 * Shared reference counter: increments by 2 on secure increment
 * request, decrements by 2 on secure decrement request. Bit #0
 * is set to 1 on non-secure increment request and reset to 0 on
 * non-secure decrement request. These counters initialize to
 * either 0, 1 or 2 upon their expect default state.
 * Counters saturate to UINT_MAX / 2.
 */
#define SHREFCNT_NONSECURE_FLAG		0x1ul
#define SHREFCNT_SECURE_STEP		0x2ul
#define SHREFCNT_MAX			(UINT_MAX / 2)

/* Return 1 if refcnt increments from 0, else return 0 */
static inline int incr_shrefcnt(unsigned int *refcnt, bool secure)
{
	int rc = !*refcnt;

	if (secure) {
		if (*refcnt < SHREFCNT_MAX) {
			*refcnt += SHREFCNT_SECURE_STEP;
			assert(*refcnt < SHREFCNT_MAX);
		}
	} else {
		*refcnt |= SHREFCNT_NONSECURE_FLAG;
	}

	return rc;
}

/* Return 1 if refcnt decrements to 0, else return 0 */
static inline int decr_shrefcnt(unsigned int *refcnt, bool secure)
{
	int  rc = 0;

	if (secure) {
		if (*refcnt < SHREFCNT_MAX) {
			if (*refcnt < SHREFCNT_SECURE_STEP)
				panic();

			*refcnt -= SHREFCNT_SECURE_STEP;
			rc = !*refcnt;
		}
	} else {
		rc = (*refcnt == SHREFCNT_NONSECURE_FLAG);
		*refcnt &= ~SHREFCNT_NONSECURE_FLAG;
	}

	return rc;
}

static inline int incr_refcnt(unsigned int *refcnt)
{
	return incr_shrefcnt(refcnt, true);
}

static inline int decr_refcnt(unsigned int *refcnt)
{
	return decr_shrefcnt(refcnt, true);
}

/*
 * Shared peripherals and resources registration
 *
 * Resources listed in enum stm32mp_shres assigned at run-time to the
 * non-secure world, to the secure world or shared by both worlds.
 * In the later case, there must exist a secure service in OP-TEE
 * for the non-secure world to access the resource.
 *
 * Resources may be a peripheral, a bus, a clock or a memory.
 *
 * Shared resources driver API functions allows drivers to register the
 * resource as secure, non-secure or shared and to get the resource
 * assignation state.
 */
#define STM32MP1_SHRES_GPIOZ(i)		(STM32MP1_SHRES_GPIOZ_0 + i)

enum stm32mp_shres {
	STM32MP1_SHRES_GPIOZ_0 = 0,
	STM32MP1_SHRES_GPIOZ_1,
	STM32MP1_SHRES_GPIOZ_2,
	STM32MP1_SHRES_GPIOZ_3,
	STM32MP1_SHRES_GPIOZ_4,
	STM32MP1_SHRES_GPIOZ_5,
	STM32MP1_SHRES_GPIOZ_6,
	STM32MP1_SHRES_GPIOZ_7,
	STM32MP1_SHRES_IWDG1,
	STM32MP1_SHRES_USART1,
	STM32MP1_SHRES_SPI6,
	STM32MP1_SHRES_I2C4,
	STM32MP1_SHRES_RNG1,
	STM32MP1_SHRES_HASH1,
	STM32MP1_SHRES_CRYP1,
	STM32MP1_SHRES_I2C6,
	STM32MP1_SHRES_RTC,
	STM32MP1_SHRES_MCU,
	STM32MP1_SHRES_PLL3,
	STM32MP1_SHRES_MDMA,
	STM32MP1_SHRES_SRAM1,
	STM32MP1_SHRES_SRAM2,
	STM32MP1_SHRES_SRAM3,
	STM32MP1_SHRES_SRAM4,

	STM32MP1_SHRES_COUNT
};

#ifdef CFG_STM32MP1_SHARED_RESOURCES
/* Register resource @id as a secure peripheral */
void stm32mp_register_secure_periph(enum stm32mp_shres id);

/* Register resource @id as a non-secure peripheral */
void stm32mp_register_non_secure_periph(enum stm32mp_shres id);

/*
 * Register resource identified by @base as a secure peripheral
 * @base: IOMEM physical base address of the resource
 */
void stm32mp_register_secure_periph_iomem(vaddr_t base);

/*
 * Register resource identified by @base as a non-secure peripheral
 * @base: IOMEM physical base address of the resource
 */
void stm32mp_register_non_secure_periph_iomem(vaddr_t base);

/*
 * Register GPIO resource as a secure peripheral
 * @bank: Bank of the target GPIO
 * @pin: Bit position of the target GPIO in the bank
 */
void stm32mp_register_secure_gpio(unsigned int bank, unsigned int pin);

/*
 * Register GPIO resource as a non-secure peripheral
 * @bank: Bank of the target GPIO
 * @pin: Bit position of the target GPIO in the bank
 */
void stm32mp_register_non_secure_gpio(unsigned int bank, unsigned int pin);

/*
 * Register pin resource of a pin control state as a secure peripheral
 * @bank: Bank of the target GPIO
 * @pin: Bit position of the target GPIO in the bank
 */
void stm32mp_register_secure_pinctrl(struct pinctrl_state *pinctrl);

/*
 * Register pin resource of a pin control state as a non-secure peripheral
 * @bank: Bank of the target GPIO
 * @pin: Bit position of the target GPIO in the bank
 */
void stm32mp_register_non_secure_pinctrl(struct pinctrl_state *pinctrl);

/* Return true if and only if resource @id is registered as secure */
bool stm32mp_periph_is_secure(enum stm32mp_shres id);

/* Return true if and only if GPIO bank @bank is registered as secure */
bool stm32mp_gpio_bank_is_secure(unsigned int bank);

/* Return true if and only if GPIO bank @bank is registered as non-secure */
bool stm32mp_gpio_bank_is_non_secure(unsigned int bank);

/* Register parent clocks of @clock (ID used in clock DT bindings) as secure */
void stm32mp_register_clock_parents_secure(unsigned long clock_id);

/* Register number of pins in the GPIOZ bank */
void stm32mp_register_gpioz_pin_count(size_t count);

#else /* CFG_STM32MP1_SHARED_RESOURCES */

static inline void stm32mp_register_secure_periph(enum stm32mp_shres id
						  __unused)
{
}

static inline void stm32mp_register_non_secure_periph(enum stm32mp_shres id
						      __unused)
{
}

static inline void stm32mp_register_secure_periph_iomem(vaddr_t base __unused)
{
}

static inline void stm32mp_register_non_secure_periph_iomem(vaddr_t base
							    __unused)
{
}

static inline void stm32mp_register_secure_gpio(unsigned int bank __unused,
						unsigned int pin __unused)
{
}

static inline void stm32mp_register_non_secure_gpio(unsigned int bank __unused,
						    unsigned int pin __unused)
{
}

static inline void
stm32mp_register_secure_pinctrl(struct pinctrl_state *pinctrl __unused)
{
}

static inline void
stm32mp_register_non_secure_pinctrl(struct pinctrl_state *pinctrl __unused)
{
}

static inline bool stm32mp_periph_is_secure(enum stm32mp_shres id __unused)
{
	return true;
}

static inline bool stm32mp_gpio_bank_is_secure(unsigned int bank __unused)
{
	return true;
}

static inline bool stm32mp_gpio_bank_is_non_secure(unsigned int bank __unused)
{
	return false;
}

static inline void stm32mp_register_clock_parents_secure(unsigned long clock_id
							 __unused)
{
}

static inline void stm32mp_register_gpioz_pin_count(size_t count __unused)
{
}
#endif /* CFG_STM32MP1_SHARED_RESOURCES */
#endif /*__STM32_UTIL_H__*/
