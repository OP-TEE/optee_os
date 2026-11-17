/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef TARGET_CONFIG_H
#define TARGET_CONFIG_H

#define GICD_BASE			UL(0x17200000)
#define GICR_BASE			UL(0x17260000)

#define AOP_CMD_DB_BASE			UL(0x80EB4000)
#define AOP_CMD_DB_SIZE			UL(0x2000)

#define MSG_RAM_SECTION_SIZE		UL(0x00010000)

#define RPMH_BASE_ADDR			UL(0x17A00000)
#define RPMH_RSC_SIZE			UL(0x40000)

#define GCC_BASE			UL(0x00100000)
#define GCC_SIZE			UL(0x001f0000)

#define DRAM0_BASE			UL(0x80000000)
#define DRAM0_SIZE			UL(0x10000000)

#define GENI_UART_REG_BASE		UL(0xa94000)

#define AOP_MSG_RAM_BASE		UL(0x0C300000)
#define AOP_MSG_RAM_SIZE		UL(0x00100000)

#define AOSS_BASE			UL(0x0b000000)
#define AOSS_SIZE			UL(0x04000000)

#endif /* TARGET_CONFIG_H */
