/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2019 Broadcom.
 */

#ifndef BCM_SOTP_H
#define BCM_SOTP_H

#include <stdint.h>
#include <tee_api.h>

TEE_Result bcm_iproc_sotp_mem_read(uint32_t row_addr, uint32_t sotp_add_ecc,
				   uint64_t *rdata);

#endif
