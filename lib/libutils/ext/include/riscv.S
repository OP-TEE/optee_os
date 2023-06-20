/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2023 Andes Technology Corporation
 */

#if __riscv_xlen == 32
#define STR       sw
#define LDR       lw
#define REGOFF(x) ((x) * 4)
#elif __riscv_xlen == 64
#define STR       sd
#define LDR       ld
#define REGOFF(x) ((x) * 8)
#endif
