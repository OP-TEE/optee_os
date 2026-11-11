/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef TARGET_CONFIG_H
#define TARGET_CONFIG_H

#define GENI_UART_REG_BASE		UL(0x894000)

#define GICD_BASE			UL(0x17100000)
#define GICR_BASE			UL(0x17180000)

#define QCOM_RNG_REG_BASE		UL(0x010c1000)

#define GCC_BASE			UL(0x00100000)
#define GCC_SIZE			UL(0x001f0000)

/* TCSR halt blocks and LPICX Q-channel */
#define TCSR_MUTEX_BASE			UL(0x01f40000)
#define TCSR_MUTEX_SIZE			UL(0x000c0000)

/* RPMH_PDC_AUDIO_SYNC_RESET, RPMH_PDC_COMPUTE_SYNC_RESET */
#define RPMH_PDC_AUDIO_BASE		UL(0x0b5e6000)
#define RPMH_PDC_AUDIO_SIZE		UL(0x00001000)
#define RPMH_PDC_COMPUTE_BASE		UL(0x0b5eb000)
#define RPMH_PDC_COMPUTE_SIZE		UL(0x00001000)

/* AOSS_CC_LPASS_RESTART, AOSS_CC_COMPUTESS_RESTART */
#define AOSS_CC_RESTART_BASE		UL(0x0c2f7000)
#define AOSS_CC_RESTART_SIZE		UL(0x00001000)
#define AOSS_CC_LPASS_RESTART		0x14
#define AOSS_CC_COMPUTESS_RESTART	0x20

/* LPASS_SYNC_RESET_CTRL (LPASS host link) */
#define LPASS_HOST_LINK_BASE		UL(0x0ef01000)
#define LPASS_HOST_LINK_SIZE		UL(0x00001000)

/* LPASS (ADSP) and Turing (CDSP) subsystem windows */
#define LPASS_BASE			UL(0x06000000)
#define LPASS_SIZE			UL(0x02000000)
#define TURING_BASE			UL(0x30000000)
#define TURING_SIZE			UL(0x02400000)

/* Blocks the clock driver and the PAS subsystems share, from those bases */
#define LPASS_QDSP6SS			0x800000
#define LPASS_ALT_RESET_Q6SS		0xeea000
#define TURING_QDSP6SS			0x2300000

#endif /* TARGET_CONFIG_H */
