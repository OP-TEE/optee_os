/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2019, HiSilicon Technologies Co., Ltd.
 */

#ifndef __HI3519AV100_H__
#define __HI3519AV100_H__

#include <mm/generic_ram_layout.h>

/* PL011 */
#define PL011_UART0_BASE		0x04540000
#define PL011_BAUDRATE			115200
#define PL011_UART0_CLK_IN_HZ		24000000

/* BootSRAM */
#define BOOTSRAM_BASE			0x04200000
#define BOOTSRAM_SIZE			0x1000

/* CPU Reset Control */
#define CPU_CRG_BASE			0x04510000
#define CPU_CRG_SIZE			0x1000

/* Sysctrl Register */
#define SYS_CTRL_BASE			0x04520000
#define SYS_CTRL_SIZE			0x1000

#endif	/* __HI3519AV100_H__ */
