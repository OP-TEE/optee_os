/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2023-2024, STMicroelectronics
 */

#ifndef __STM32MP_PM_H__
#define __STM32MP_PM_H__

/*
 * The PSCI topology is defined in TF-A, with 5 power levels supported in
 * the first parameter a0="Max power level powered down" of TF-A SPD hooks
 *
 * power level                (associated low power mode for a0)
 * 0: CPU1 core#0 or core#1   (Stop1 or LP-Stop1)
 * 1: D1 domain               (LPLV-Stop1)
 * 2: LPLV D1                 (Stop2 or LP-Stop2)
 * 3: D2                      (LPLV-Stop1)
 * 4: LPLV D2                 (Standby)
 * 5: MAX                     (PowerOff)
 *
 * these power level are only managed in power driver (PMIC), for pm function
 * use the 2 associated parameters:
 * - PM_HINT_CONTEXT_STATE : advertise driver to save all their context in DDR
 *                           (self refresh) for standby mode
 * - PM_HINT_CLOCK_STATE : advertise driver to interrupt operation when clock
 *                         are stalled for the other low power modes
 */
#define PM_CORE_LEVEL           0
#define PM_D1_LEVEL             1
#define PM_D1_LPLV_LEVEL        2
#define PM_D2_LEVEL             3
#define PM_D2_LPLV_LEVEL        4
#define PM_MAX_LEVEL            5

#endif /*__STM32MP_PM_H__*/
