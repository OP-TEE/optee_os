/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2017, Schneider Electric
 * Copyright (c) 2020, Linaro Limited
 */

#ifndef RZN1_TZ_H
#define RZN1_TZ_H

#include <util.h>

/* TZ config registers */
#define FW_STATIC_TZA_INIT	0x4000C0D0
#define FW_STATIC_TZA_TARG	0x4000C0D4

/* TZ initiatior ports */
#define TZ_INIT_CSB_SEC		BIT(7)  /* CoreSight AHB */
#define TZ_INIT_CSA_SEC		BIT(6)  /* CoreSight AXI */
#define TZ_INIT_YS_SEC		BIT(5)  /* Cortex-M3 System Bus interface */
#define TZ_INIT_YC_SEC		BIT(4)  /* Cortex-M3 ICode interface */
#define TZ_INIT_YD_SEC		BIT(3)  /* Cortex-M3 DCode interface */
#define TZ_INIT_Z_SEC		BIT(2)  /* Packet Engine */
#define TZ_INIT_I_SEC		BIT(1)  /* Peripheral Group */
#define TZ_INIT_F_SEC		BIT(0)  /* Peripheral Group */

/* TZ target ports */
#define TZ_TARG_W_SEC		BIT(14) /* RTC */
#define TZ_TARG_PC_SEC		BIT(9)  /* DDR2/3 Controller */
#define TZ_TARG_RA_SEC		BIT(8)  /* CoreSight */
#define TZ_TARG_QB_SEC		BIT(7)  /* System Control */
#define TZ_TARG_QA_SEC		BIT(6)  /* PG0 */
#define TZ_TARG_NB_SEC		BIT(5)  /* Packet Engine */
#define TZ_TARG_NA_SEC		BIT(4)  /* Public Key Processor */
#define TZ_TARG_K_SEC		BIT(3)  /* Peripheral Group */
#define TZ_TARG_J_SEC		BIT(2)  /* Peripheral Group */
#define TZ_TARG_UB_SEC		BIT(1)  /* 2MB SRAM */
#define TZ_TARG_UA_SEC		BIT(0)  /* 2MB SRAM */

#endif /* RZN1_TZ_H */
