/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2019 Bryan O'Donoghue
 * Copyright 2019 NXP
 *
 * Bryan O'Donoghue <bryan.odonoghue@linaro.org>
 */

#ifndef __IMX_CAAM_H__
#define __IMX_CAAM_H__

#include <compiler.h>
#include <imx-regs.h>
#include <stdint.h>
#include <types_ext.h>

struct imx_caam_job_ring {
	uint32_t			jrmidr_ms;
	uint32_t			jrmidr_ls;
} __packed;

#define CAAM_NUM_JOB_RINGS		4

/* CAAM ownersip definition bits */
#define JROWN_NS			BIT(3)
#define JROWN_MID			0x01

/* i.MX6 CAAM clocks bits  */
#define CCM_CCGR0		0x0068
#define CCM_CCGR6		0x0080

#define CCM_CCGR0_CAAM_WRAPPER_IPG	SHIFT_U32(3, 12)
#define CCM_CCGR0_CAAM_SECURE_MEM	SHIFT_U32(3, 8)
#define CCM_CCGR0_CAAM_WRAPPER_ACLK	SHIFT_U32(3, 10)
#define CCM_CCGR6_EMI_SLOW		SHIFT_U32(3, 10)

/* A basic sub-set of the CAAM */
struct imx_caam_ctrl {
	uint32_t			res0;
	uint32_t			mcfgr;
	uint32_t			res1;
	uint32_t			scfgr;
	struct imx_caam_job_ring	jr[CAAM_NUM_JOB_RINGS];
} __packed;

#endif /* __IMX_CAAM_H__ */
