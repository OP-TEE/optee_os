/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2017-2019 NXP
 *
 * Brief   CAAM Random Number Generator manager header.
 */
#ifndef __CAAM_RNG_H__
#define __CAAM_RNG_H__

/*
 * Initialize the RNG module to generate data
 *
 * @ctrl_addr   Controller base address
 */
enum caam_status caam_rng_init(vaddr_t ctrl_addr);

/* Instantiates the RNG State Handles if not already done */
enum caam_status caam_rng_instantiation(void);

#endif /* __CAAM_RNG_H__ */
