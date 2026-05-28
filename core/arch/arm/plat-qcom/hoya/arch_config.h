/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2024, Linaro Limited
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef ARCH_CONFIG_H
#define ARCH_CONFIG_H

#define GICD_BASE			UL(0x17a00000)
#define GICR_BASE			UL(0x17a60000)

#define RAMBLUR_PIMEM_REG_BASE		UL(0x610000)
#define SEC_PRNG_REG_BASE		UL(0x010D1000)

#define AOP_MSG_RAM_BASE		UL(0x0C300000)
#define AOP_MSG_RAM_SIZE		UL(0x00100000)

#define RPMH_BASE_ADDR			UL(0x18200000)
#define RPMH_RSC_SIZE			UL(0x40000)

#define SECURITY_CONTROL_BASE		UL(0x00780000)
#define SECURITY_CONTROL_SIZE		UL(0x10000)

#define TCSR_MUTEX_BASE			UL(0x01F40000)
#define TCSR_MUTEX_SIZE			UL(0x40000)

#endif /* ARCH_CONFIG_H */
