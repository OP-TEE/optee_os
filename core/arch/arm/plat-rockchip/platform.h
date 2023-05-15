/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2019, Theobroma Systems Design und Consulting GmbH
 */

#ifndef PLAT_ROCKCHIP_PLATFORM_H
#define PLAT_ROCKCHIP_PLATFORM_H

int platform_secure_init(void);
int platform_secure_ddr_region(int rgn, paddr_t st, size_t sz);

#endif
