/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, STMicroelectronics - All Rights Reserved
 */

#ifndef __DRIVERS_STPMIC2_H
#define __DRIVERS_STPMIC2_H

size_t plat_stpmic2_get_lp_mode_count(void);
const char *plat_stpmic2_get_lp_mode_name(int mode);

TEE_Result plat_stpmic2_supplied_init(struct regulator *regulator);

TEE_Result stpmic2_apply_pm_state(struct regulator *regulator, uint8_t mode);

TEE_Result stpmic2_suspend_regulator(struct regulator *regulator, uint8_t mode);
TEE_Result stpmic2_resume_regulator(struct regulator *regulator);

#endif /*__DRIVERS_STPMIC2_H*/
