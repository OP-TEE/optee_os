/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2019 Broadcom.
 */

#ifndef BCM_SOTP_H
#define BCM_SOTP_H

#include <stdint.h>
#include <tee_api.h>

#define SOTP_ECC_ERR_DETECT	BIT64(63)

/**
 * Reads from sotp fuse at given row address.
 * @row_addr: row address
 * @sotp_add_ecc: ecc memory support flag
 * @rdata: pointer to sotp data value
 * @returns TEE_Result value
 */
TEE_Result bcm_iproc_sotp_mem_read(uint32_t row_addr, bool sotp_add_ecc,
				   uint64_t *rdata);

/**
 * Writes to sotp fuse at given row address.
 * @row_addr: row address
 * @sotp_add_ecc: ecc memory support flag
 * @wdata: data to be written to sotp fuse
 * @returns TEE_Result value
 */
TEE_Result bcm_iproc_sotp_mem_write(uint32_t row_addr, bool sotp_add_ecc,
				    uint64_t wdata);

#endif
