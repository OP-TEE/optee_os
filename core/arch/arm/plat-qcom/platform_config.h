/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2024, Linaro Limited
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef PLATFORM_CONFIG_H
#define PLATFORM_CONFIG_H

#include <mm/generic_ram_layout.h>
#include <arch_config.h>
#include <target_config.h>

/* Make stacks aligned to data cache line length */
#define STACK_ALIGNMENT			64

#define MAX_XLAT_TABLES		(40 + (CFG_RESERVED_VASPACE_SIZE) / \
				 (CORE_MMU_PGDIR_SIZE) + 5)

#endif /*PLATFORM_CONFIG_H*/
