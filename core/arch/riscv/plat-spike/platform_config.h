/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2022 NXP
 *
 * Brief   Spike platform configuration.
 */

#ifndef PLATFORM_CONFIG_H
#define PLATFORM_CONFIG_H

#include <mm/generic_ram_layout.h>

#ifndef HTIF_BASE
#define HTIF_BASE	0x40008000
#endif

/* CLINT */
#ifndef CLINT_BASE
#define CLINT_BASE	0x02000000
#endif

#endif
