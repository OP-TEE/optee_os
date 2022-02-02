/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2018-2022, STMicroelectronics
 */

#ifndef __STM32_UTIL_H__
#define __STM32_UTIL_H__

#include <assert.h>
#include <drivers/clk.h>
#include <kernel/panic.h>
#include <stdbool.h>
#include <stdint.h>
#include <tee_api_types.h>
#include <types_ext.h>

/* SoC versioning and device ID */
TEE_Result stm32mp1_dbgmcu_get_chip_dev_id(uint32_t *chip_dev_id);

/* Crypto HW support */
bool stm32mp_supports_hw_cryp(void);

/*  Second core support */
bool stm32mp_supports_second_core(void);

/* Get device ID from SYSCFG registers */
uint32_t stm32mp_syscfg_get_chip_dev_id(void);

/*
 * OPP service support per hardware constraints
 * @opp_id: OPP support identifier read from DT property opp-hw-support
 * Return true if hardware supports the OPP, return false otherwise
 */
bool stm32mp_supports_cpu_opp(uint32_t opp_id);

/* Backup registers and RAM utils */
vaddr_t stm32mp_bkpreg(unsigned int idx);

/* Platform util for the RCC drivers */
vaddr_t stm32_rcc_base(void);

/* Erase ESRAM3 */
TEE_Result stm32mp_syscfg_erase_sram3(void);

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

extern const struct clk_ops stm32mp1_clk_ops;

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

bool stm32mp_allow_probe_shared_device(const void *fdt, int node);

#if defined(CFG_STM32MP15) && defined(CFG_WITH_PAGER)
/*
 * Return the SRAM alias physical address related to @pa when applicable or
 * @pa if it does not relate to an SRAMx non-aliased memory address.
 */
paddr_t stm32mp1_pa_or_sram_alias_pa(paddr_t pa);

/* Return whether or not the physical address range intersec pager secure RAM */
bool stm32mp1_ram_intersect_pager_ram(paddr_t base, size_t size);
#else
static inline paddr_t stm32mp1_pa_or_sram_alias_pa(paddr_t pa)
{
	return pa;
}

static inline bool stm32mp1_ram_intersect_pager_ram(paddr_t base __unused,
						    size_t size __unused)
{
	return false;
}
#endif /*CFG_STM32MP15 && CFG_WITH_PAGER*/

/* Print a message and reset the system */
void __noreturn do_reset(const char *str);

#endif /*__STM32_UTIL_H__*/
