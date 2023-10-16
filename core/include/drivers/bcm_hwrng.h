/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2019 Broadcom.
 */

#ifndef __DRIVERS_BCM_HWRNG_H
#define __DRIVERS_BCM_HWRNG_H

#include <stdlib.h>

uint32_t bcm_hwrng_read_rng(uint32_t *p_out, uint32_t words_to_read);

#endif /* __DRIVERS_BCM_HWRNG_H */
