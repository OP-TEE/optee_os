/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2023 NXP
 */

#include <stdint.h>

/*
 * Read the SRC GPR ARG register for the given core number
 * @cpu	Core number
 */
uint32_t imx_get_src_gpr_arg(unsigned int cpu);

/*
 * Set the SRC GPR ARG register for the given core number
 * @cpu	Core number
 * @val	Register value to set
 */
void imx_set_src_gpr_arg(unsigned int cpu, uint32_t val);

/*
 * Read the SRC GPR ENTRY register for the given core number
 * @cpu	Core number
 */
uint32_t imx_get_src_gpr_entry(unsigned int cpu);

/*
 * Set the SRC GPR ENTRY register for the given core number
 * @cpu	Core number
 * @val	Register value to set
 */
void imx_set_src_gpr_entry(unsigned int cpu, uint32_t val);

/*
 * Release the given core
 * @cpu Core number
 */
void imx_src_release_secondary_core(unsigned int cpu);

/*
 * Shutdown the given core
 * @cpu Core number
 */
void imx_src_shutdown_core(unsigned int cpu);

/*
 * GPC Core 1 power down
 */
void imx_gpcv2_set_core1_pup_by_software(void);
