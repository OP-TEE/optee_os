/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef TARGET_CONFIG_H
#define TARGET_CONFIG_H

/* DRAM0_SIZE covers the largest supported variant. */
#define DRAM0_BASE			UL(0x40000000)
#define DRAM0_SIZE			UL(0x100000000)

/* QUPV3_0 SE4 */
#define GENI_UART_REG_BASE		UL(0x04a90000)

/* GIC-500 redistributor (GICD_BASE is common to the family). */
#define GICR_BASE			UL(0x0f300000)

#define QCOM_RNG_REG_BASE		UL(0x04453000)

#endif /* TARGET_CONFIG_H */
