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
/* clock configuration */
#define I2C_CLK_CGR(__x)	CCM_CCRG_I2C##__x
/* iomux configuration */
#define IOMUXC_I2C1_SCL_CFG_OFF	0x47C
#define IOMUXC_I2C1_SDA_CFG_OFF	0x480
#define IOMUXC_I2C1_SCL_MUX_OFF	0x214
#define IOMUXC_I2C1_SDA_MUX_OFF	0x218
#define IOMUXC_I2C_MUX_VAL	0x010
#define IOMUXC_I2C_CFG_VAL	0x1c3
#endif

#if defined(CFG_MX6ULL)
#include <registers/imx6.h>
/* clock configuration*/
#define I2C_CLK_CGRBM(__x)	BM_CCM_CCGR2_I2C##__x##_SERIAL
#define I2C_CLK_CGR(__x)	CCM_CCGR2
/* iomux configuration*/
#define IOMUXC_I2C1_SCL_CFG_OFF	0x340
#define IOMUXC_I2C1_SDA_CFG_OFF	0x344
#define IOMUXC_I2C1_SCL_MUX_OFF	0xb4
#define IOMUXC_I2C1_SDA_MUX_OFF	0xb8
#define IOMUXC_I2C_MUX_VAL	0x12
#define IOMUXC_I2C_CFG_VAL	0x1b8b0
#define IOMUXC_I2C1_SCL_INP_OFF	0x5a4
#define IOMUXC_I2C1_SDA_INP_OFF	0x5a8
#define I2C_INP_SCL(__x)	(IOMUXC_I2C1_SCL_INP_OFF + ((__x) - 1) * 0x8)
#define I2C_INP_SDA(__x)	(IOMUXC_I2C1_SDA_INP_OFF + ((__x) - 1) * 0x8)
#define I2C_INP_VAL(__x)	(((__x) == IOMUXC_I2C1_SCL_INP_OFF) ? 0x1 : 0x2)
#endif

TEE_Result imx_i2c_write(uint8_t bid, uint8_t chip, const uint8_t *p, int l);
TEE_Result imx_i2c_read(uint8_t bid, uint8_t chip, uint8_t *p, int l);
TEE_Result imx_i2c_probe(uint8_t bid, uint8_t chip);
TEE_Result imx_i2c_init(uint8_t bid, int bps);

#endif /*__DRIVERS_IMX_I2C_H*/
