/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2020 Foundries.io
 * Jorge Ramirez-Ortiz <jorge@foundries.io>
 */
#ifndef __DRIVERS_IMX_I2C_H
#define __DRIVERS_IMX_I2C_H

#include <stdint.h>
#include <tee_api_types.h>

#if defined(CFG_MX8MM)
#include <registers/imx8m.h>
#define I2C_CLK_CGR(__x)	CCM_CCRG_I2C##__x

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

#if defined(CFG_MX6ULL)
#include <registers/imx6.h>
#define I2C_CLK_CGRBM(__x)	BM_CCM_CCGR2_I2C##__x##_SERIAL
#define I2C_CLK_CGR(__x)	CCM_CCGR2

#define IOMUXC_I2C1_SCL_CFG	0x340
#define IOMUXC_I2C1_SDA_CFG	0x344
#define I2C_CFG_SCL(__x)	(IOMUXC_I2C1_SCL_CFG + ((__x) - 1) * 0x8)
#define I2C_CFG_SDA(__x)	(IOMUXC_I2C1_SDA_CFG + ((__x) - 1) * 0x8)

#define IOMUXC_I2C1_SCL_MUX	0xb4
#define IOMUXC_I2C1_SDA_MUX	0xb8
#define I2C_MUX_SCL(__x)	(IOMUXC_I2C1_SCL_MUX + ((__x) - 1) * 0x8)
#define I2C_MUX_SDA(__x)	(IOMUXC_I2C1_SDA_MUX + ((__x) - 1) * 0x8)

#define IOMUXC_I2C1_SCL_INP	0x5a4
#define IOMUXC_I2C1_SDA_INP	0x5a8
#define I2C_INP_SCL(__x)	(IOMUXC_I2C1_SCL_INP + ((__x) - 1) * 0x8)
#define I2C_INP_SDA(__x)	(IOMUXC_I2C1_SDA_INP + ((__x) - 1) * 0x8)

#define I2C_MUX_VAL(__x)	0x12
#define I2C_CFG_VAL(__x)	0x1b8b0
#define I2C_INP_VAL(__x)	(((__x) == IOMUXC_I2C1_SCL_INP) ? 0x1 : 0x2)
#endif

TEE_Result imx_i2c_write(uint8_t bid, uint8_t chip, const uint8_t *p, int l);
TEE_Result imx_i2c_read(uint8_t bid, uint8_t chip, uint8_t *p, int l);
TEE_Result imx_i2c_probe(uint8_t bid, uint8_t chip);
TEE_Result imx_i2c_init(uint8_t bid, int bps);

#endif /*__DRIVERS_IMX_I2C_H*/
