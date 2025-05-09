/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2024, Linaro Limited
 */

#ifndef PLATFORM_CONFIG_H
#define PLATFORM_CONFIG_H

#include <mm/generic_ram_layout.h>

/* Make stacks aligned to data cache line length */
#define STACK_ALIGNMENT			64

#if defined(PLATFORM_FLAVOR_sc7280)

#define DRAM0_BASE			UL(0x80000000)
#define DRAM0_SIZE			UL(0x3a800000)

#define DRAM1_BASE			ULL(0xc0000000)
#define DRAM1_SIZE			ULL(0x01800000)

#define DRAM2_BASE			ULL(0xc3400000)
#define DRAM2_SIZE			ULL(0x3cc00000)

#define DRAM3_BASE			ULL(0x100000000)
#define DRAM3_SIZE			ULL(0x100000000)

#define SYS_COUNTER_FREQ_IN_TICKS	UL(19200000)

#define UART0_BASE			UL(0x994000)
#define CONSOLE_UART_BASE		UART0_BASE

/* GIC related constants */
#define GICD_BASE			UL(0x17a00000)
#define GICR_BASE			UL(0x17a60000)

#define GCC_BASE UL(0x100000)
#define WPSS_BASE UL(0x08a00000)
#define ADSP_BASE UL(0x03000000)
#define ADSP_LPASS_EFUSE UL(0x0355b000)

#endif

/* common error codes */
#define QCOM_SCM_V2_EBUSY	-12
#define QCOM_SCM_ENOMEM		-5
#define QCOM_SCM_EOPNOTSUPP	-4
#define QCOM_SCM_EINVAL_ADDR	-3
#define QCOM_SCM_EINVAL_ARG	-2
#define QCOM_SCM_ERROR		-1
#define QCOM_SCM_INTERRUPTED	1
#define QCOM_SCM_WAITQ_SLEEP	2

#define PLAT_ARM_CLUSTER_COUNT		U(2)

#endif /*PLATFORM_CONFIG_H*/
