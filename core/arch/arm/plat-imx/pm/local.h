/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2023 NXP
 */

#include <stdint.h>

/*
 * Read the SRC GPR register for the given core number
 * @cpu	Core number
 */
uint32_t imx_get_src_gpr(int cpu);

/*
 * Set the SRC GPR register for the given core number
 * @cpu	Core number
 * @val	Register value to set
 */
void imx_set_src_gpr(int cpu, uint32_t val);
