/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2021, Microchip
 */

#ifndef __DRIVERS_ATMEL_SAIC_H
#define __DRIVERS_ATMEL_SAIC_H

#include <tee_api_types.h>
#include <util.h>

#define AT91_AIC_WPKEY	0x414943

#define AT91_AIC_SSR		0x0
#define	AT91_AIC_SSR_ITSEL_MASK	GENMASK_32(6, 0)

#define AT91_AIC_SMR		0x4
#define	AT91_AIC_SMR_SRC_SHIFT	5
#define	AT91_AIC_SMR_LEVEL	SHIFT_U32(0, AT91_AIC_SMR_SRC_SHIFT)
#define	AT91_AIC_SMR_NEG_EDGE	SHIFT_U32(1, AT91_AIC_SMR_SRC_SHIFT)
#define	AT91_AIC_SMR_HIGH_LEVEL	SHIFT_U32(2, AT91_AIC_SMR_SRC_SHIFT)
#define	AT91_AIC_SMR_POS_EDGE	SHIFT_U32(3, AT91_AIC_SMR_SRC_SHIFT)

#define AT91_AIC_SVR	0x8
#define AT91_AIC_IVR	0x10
#define AT91_AIC_ISR	0x18

#define AT91_AIC_IPR0	0x20
#define AT91_AIC_IPR1	0x24
#define AT91_AIC_IPR2	0x28
#define AT91_AIC_IPR3	0x2c
#define AT91_AIC_IMR	0x30
#define AT91_AIC_CISR	0x34
#define AT91_AIC_EOICR	0x38
#define AT91_AIC_SPU	0x3c
#define AT91_AIC_IECR	0x40
#define AT91_AIC_IDCR	0x44
#define AT91_AIC_ICCR	0x48
#define AT91_AIC_ISCR	0x4c
#define AT91_AIC_DCR	0x6c
#define AT91_AIC_WPMR	0xe4
#define AT91_AIC_WPSR	0xe8

TEE_Result atmel_saic_setup(void);

#endif /*__DRIVERS_ATMEL_SAIC_H*/
