/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2023 Andes Technology Corporation
 * Copyright (c) 2026, RISCStar Solutions Limited
 */

#if __riscv_xlen == 32
#define STR       sw
#define LDR       lw
#define REGOFF(x) ((x) * 4)
#define FST       fsd
#define FLD       fld
#define REG_S	  sd
#define REG_L     ld
#define FP_REG_BYTES    8
#elif __riscv_xlen == 64
#define STR       sd
#define LDR       ld
#define REGOFF(x) ((x) * 8)
#define FST       fsw
#define FLD       flw
#define REG_S	  sw
#define REG_L     lw
#define FP_REG_BYTES    4
#endif

