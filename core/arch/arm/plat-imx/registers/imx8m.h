/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2017-2019 NXP
 */

#ifndef __IMX8M_H__
#define __IMX8M_H__

#include <registers/imx8m-crm.h>

#define GICD_BASE	0x38800000
#define GICR_BASE	0x38880000
#define UART1_BASE	0x30860000
#define UART2_BASE	0x30890000
#define UART3_BASE	0x30880000
#define UART4_BASE	0x30A60000
#define TZASC_BASE	0x32F80000
#define CAAM_BASE	0x30900000
#define CCM_BASE	0x30380000
#define CCM_SIZE	0x10000
#define ANATOP_BASE	0x30360000
#define IOMUXC_BASE	0x30330000
#define OCOTP_BASE	0x30350000
#define OCOTP_SIZE	0x10000
#define SNVS_BASE	0x30370000

#ifdef CFG_MX8MQ
#define DIGPROG_OFFSET	  0x06c
#define OCOTP_SW_INFO_B1  0x40
#define OCOTP_SW_MAGIC_B1 0xFF0055AA
#endif
#if defined(CFG_MX8MM) || defined(CFG_MX8MN) || defined(CFG_MX8MP)
#define DIGPROG_OFFSET	0x800
#endif

#if defined(CFG_MX8MM) || defined(CFG_MX8MQ)
#define I2C1_BASE		0x30a20000
#define I2C2_BASE		0x30a30000
#define I2C3_BASE		0x30a40000
#define I2C4_BASE		0x30a50000

#define IOMUXC_I2C1_SCL_CFG_OFF	0x47C
#define IOMUXC_I2C1_SDA_CFG_OFF	0x480
#define IOMUXC_I2C1_SCL_MUX_OFF	0x214
#define IOMUXC_I2C1_SDA_MUX_OFF	0x218
#endif

#endif /* __IMX8M_H__ */
