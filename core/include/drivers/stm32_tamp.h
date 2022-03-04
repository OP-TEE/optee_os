/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2021-2022, STMicroelectronics
 */

#ifndef __DRIVERS_STM32_TAMP_H__
#define __DRIVERS_STM32_TAMP_H__

#include <compiler.h>
#include <stdint.h>
#include <tee_api_types.h>

/*
 * struct stm32_bkpregs_conf - Interface for stm32_tamp_set_secure_bkpregs()
 * @nb_zone1_regs - Number of backup registers in zone 1
 * @nb_zone2_regs - Number of backup registers in zone 2
 *
 * TAMP backup registers access permissions
 *
 * Zone 1: read/write in secure state, no access in non-secure state
 * Zone 2: read/write in secure state, read-only in non-secure state
 * Zone 3: read/write in secure state, read/write in non-secure state
 *
 * Protection zone 1
 * If nb_zone1_regs == 0 no backup register are in zone 1.
 * Otherwise backup registers from TAMP_BKP0R to TAMP_BKP<x>R are in zone 1,
 * with <x> = (@nb_zone1_regs - 1).
 *
 * Protection zone 2
 * If nb_zone2_regs == 0 no backup register are in zone 2.
 * Otherwise backup registers from TAMP_BKP<y>R ro TAMP_BKP<z>R are in zone 2,
 * with <y> = @nb_zone1_regs and <z> = (@nb_zone1_regs1 + @nb_zone2_regs - 1).
 *
 * Protection zone 3
 * Backup registers from TAMP_BKP<t>R to last backup register are in zone 3,
 * with <t> = (@nb_zone1_regs1 + @nb_zone2_regs).
 */
struct stm32_bkpregs_conf {
	uint32_t nb_zone1_regs;
	uint32_t nb_zone2_regs;
};

#ifdef CFG_STM32_TAMP
/*
 * stm32_tamp_set_secure_bkprwregs() - Configure backup registers zone.
 * @conf - Configuration to be programmed
 */
TEE_Result stm32_tamp_set_secure_bkpregs(struct stm32_bkpregs_conf *conf);
#else
static inline
TEE_Result stm32_tamp_set_secure_bkpregs(struct stm32_bkpregs_conf *c __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}
#endif
#endif /* __DRIVERS_STM32_TAMP_H__ */
