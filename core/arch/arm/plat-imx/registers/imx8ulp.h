/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2021 NXP
 */
#ifndef __IMX8ULP_H__
#define __IMX8ULP_H__

#include <registers/imx8ulp-crm.h>

#define GICD_BASE   0x2d400000
#define GICR_BASE   0x2d440000
#define UART4_BASE  0x29390000
#define UART5_BASE  0x293a0000
#define CAAM_BASE   0x292e0000
#define CAAM_SIZE   0x10000
#define PCC3_BASE   0x292d0000
#define PCC3_SIZE   0x1000
#define AIPS3_BASE  0x29000000
#define AIPS3_SIZE  0x400000
#define SECMEM_BASE 0x00100000
#define SECMEM_SIZE 0x80000
#define MU_BASE	    0x27020000
#define MU_SIZE	    0x10000

#endif /* __IMX8ULP_H__ */
