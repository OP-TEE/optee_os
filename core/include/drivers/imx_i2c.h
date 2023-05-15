/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2020 Foundries.io
 * Jorge Ramirez-Ortiz <jorge@foundries.io>
 */
#ifndef __DRIVERS_IMX_I2C_H
#define __DRIVERS_IMX_I2C_H

#include <stdint.h>
#include <tee_api_types.h>

TEE_Result imx_i2c_write(uint8_t bid, uint8_t chip, const uint8_t *p, int l);
TEE_Result imx_i2c_read(uint8_t bid, uint8_t chip, uint8_t *p, int l);
TEE_Result imx_i2c_probe(uint8_t bid, uint8_t chip);
TEE_Result imx_i2c_init(uint8_t bid, int bps);

#endif /*__DRIVERS_IMX_I2C_H*/
