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
#define ANATOP_BASE	0x30360000
#define IOMUXC_BASE	0x30330000

#ifdef CFG_MX8MQ
#define DIGPROG_OFFSET	0x06c
#endif
#if defined(CFG_MX8MM) || defined(CFG_MX8MN)
#define DIGPROG_OFFSET	0x800
#endif

#if defined(CFG_MX8MM)
#define I2C1_BASE		0x30a20000
#define I2C2_BASE		0x30a30000
#define I2C3_BASE		0x30a40000

#define IOMUXC_I2C1_SCL_CFG	0x47C
#define IOMUXC_I2C1_SDA_CFG	0x480
#define I2C_CFG_SCL(__x)	(IOMUXC_I2C1_SCL_CFG + ((__x) - 1) * 0x8)
#define I2C_CFG_SDA(__x)	(IOMUXC_I2C1_SDA_CFG + ((__x) - 1) * 0x8)

#define IOMUXC_I2C1_SCL_MUX	0x214
#define IOMUXC_I2C1_SDA_MUX	0x218
#define I2C_MUX_SCL(__x)	(IOMUXC_I2C1_SCL_MUX + ((__x) - 1) * 0x8)
#define I2C_MUX_SDA(__x)	(IOMUXC_I2C1_SDA_MUX + ((__x) - 1) * 0x8)

#define IOMUXC_I2C_MUX_VAL	0x010
#define IOMUXC_I2C_CFG_VAL	0x1c3
#define I2C_MUX_VAL(__x)	IOMUXC_I2C_MUX_VAL
#define I2C_CFG_VAL(__x)	IOMUXC_I2C_CFG_VAL
#endif

#endif /* __IMX8M_H__ */
