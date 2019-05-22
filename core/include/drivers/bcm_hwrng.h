/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2019 Broadcom.
 */

#ifndef BCM_HWRNG_H
#define BCM_HWRNG_H

#include <stdlib.h>

uint32_t bcm_hwrng_read_rng(uint32_t *p_out, uint32_t words_to_read);

#endif /* BCM_HWRNG_H */
