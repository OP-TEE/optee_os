/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2026 Linumiz
 */

#ifndef __DRIVERS_SUNXI_SID_H
#define __DRIVERS_SUNXI_SID_H

#include <stdint.h>
#include <tee_api_types.h>

#define SUNXI_SID_CHIP_ID_REG		0x00
#define SUNXI_SID_HUK_REG		0x50

/**
 * Reads from sunxi sid efuse register.
 * @buf: pointer to store value
 * @len: length of data to be read
 * @offset: offset of the efuse register
 * @return TEE_Result value
 */
TEE_Result sunxi_sid_read_otp(uint8_t *buf, size_t len, uint32_t offset);

#endif
