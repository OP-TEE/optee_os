/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015, Linaro Limited
 * Copyright (c) 2022, Huawei Technologies Co., Ltd
 */

#ifndef PLATFORM_CONFIG_H
#define PLATFORM_CONFIG_H

#include <mm/generic_ram_layout.h>

/* Make stacks aligned to data cache line length */
#define STACK_ALIGNMENT		64

/*
 * HiSilicon D06 memory map
 *
 * Note: the physical address ranges below correspond to DRAM which is
 * non-secure by default. Therefore, the terms TZDRAM and TZSRAM may not
 * reflect the reality and only indicate areas that "would normally be"
 * secure DRAM and secure SRAM in a more complete implementation.
 * The memory map was defined like this for lack of better documentation.
 * It is good enough for development/testing purposes.
 *
 * CFG_WITH_PAGER=n
 *
 *  0x8000_0000                                  -
 *    Linux/other                                | DRAM1
 *  0x3000_0000                                  -
 *    Linux/other                                | reserved
 *  0x2800_0000                                  -
 *    TA RAM: 32 MiB                             |
 *  0x2600_0000                                  | TZDRAM
 *    TEE RAM: 32 MiB (TEE_RAM_VA_SIZE)		 |
 *  0x2400_0000 [TZDRAM_BASE, TEE_LOAD_ADDR]     -
 *    Shared memory: 64 MB                       | SHMEM
 *  0x2000_0000                                  -
 *    Linux/other                                | DRAM0
 *  0x0000_0000 [DRAM0_BASE]                     -
 *
 */
#define DRAM0_BASE  0x00000000
#define DRAM0_SIZE  0x20000000

#define DRAM1_BASE  0x30000000
#define DRAM1_SIZE  0x50000000

#endif /* PLATFORM_CONFIG_H */
