/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2017-2019 NXP
 */

#ifndef __IMX8M_H__
#define __IMX8M_H__

#define GICD_BASE	0x38800000
#define GICR_BASE	0x38880000
#define UART1_BASE	0x30860000
#define UART2_BASE	0x30890000
#define UART3_BASE	0x30880000
#define UART4_BASE	0x30A60000
#define TZASC_BASE	0x32F80000
#define CAAM_BASE	0x30900000
#define ANATOP_BASE	0x30360000

#ifdef CFG_IMX8MQ
#define DIGPROG_OFFSET	0x06c
#endif
#if defined(CFG_IMX8MM) || defined(CFG_IMX8MN)
#define DIGPROG_OFFSET	0x800
#endif

#endif /* __IMX8M_H__ */
