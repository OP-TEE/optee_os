/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2022 NXP
 *
 * Brief   Spike platform configuration.
 */

#ifndef PLATFORM_CONFIG_H
#define PLATFORM_CONFIG_H

#define TEE_RAM_START		CFG_TDDRAM_START
#define TEE_LOAD_ADDR		TEE_RAM_START
#define TEE_RAM_VA_SIZE		(1024 * 1024)

#endif
