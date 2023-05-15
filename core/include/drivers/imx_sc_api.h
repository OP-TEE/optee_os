/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2016 Freescale Semiconductor, Inc.
 * Copyright 2017-2021 NXP
 */
#ifndef __DRIVERS_IMX_SC_API_H
#define __DRIVERS_IMX_SC_API_H

#include <tee_api_types.h>

/*
 * Initializes the Secure Controller
 */
TEE_Result imx_sc_driver_init(void);

/*
 * Enables a CAAM Job Ring for the secure world with the following steps:
 *  - Assign CAAM JR resources to secure world
 *  - Power ON CAAM JR resources
 *
 * @jr_index Index of the CAAM Job Ring to enable
 */
TEE_Result imx_sc_rm_enable_jr(unsigned int jr_index);

/*
 * Starts the random number generator and returns the RNG status.
 *
 * Note that the RNG is started automatically after all CPUs are booted. This
 * function can then be used to start the RNG earlier or to check the RNG
 * status.
 */
TEE_Result imx_sc_seco_start_rng(void);
#endif /* __DRIVERS_IMX_SC_API_H */
