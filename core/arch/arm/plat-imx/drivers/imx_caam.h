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

/* Descriptor and MKVB Definitions */
#define MKVB_SIZE			32
#define MKVB_DESC_SEQ_OUT		0xf8000020
#define MKVB_DESC_HEADER		0xb0800004
#define MKVB_DESC_BLOB			0x870d0002

/* PRIBLOB Bits */
#define PRIBLOB_11			3

/* JR Bits */
#define MKVB_JR				1
#define MKVB_JR1_START			2

/* jr configuration registers */
struct imx_caam_jr_ctrl {
	uint32_t	irbar;
	uint32_t	irbar_ls;
	uint8_t		padding[4];
	uint32_t	irsr;
	uint8_t		padding2[4];
	uint32_t	irsar;
	uint8_t		padding3[4];
	uint32_t	irjar;
	uint32_t	orbar;
	uint32_t	orbar_ls;
	uint8_t		padding4[4];
	uint32_t	orsr;
	uint8_t		padding5[4];
	uint32_t	orjrr;
	uint8_t		padding6[4];
	uint32_t	orsfr;
	uint8_t		padding7[4];
	uint32_t	jrstar;
	uint8_t		padding8[4];
	uint32_t	jrintr;
	uint32_t	jrcfgr_ms;
	uint32_t	jrcfgr_ls;
	uint8_t		padding9[4];
	uint32_t	irrir;
	uint8_t		padding10[4];
	uint32_t	orwir;
	uint8_t		padding11[4];
	uint32_t	jrcr;
	uint8_t		padding12[1688];
	uint32_t	jraav;
	uint8_t		padding13[2292];
} __packed;

/* A basic sub-set of the CAAM */
struct imx_caam_ctrl {
	uint32_t			res0;
	uint32_t			mcfgr;
	uint32_t			res1;
	uint32_t			scfgr;
	struct imx_caam_job_ring	jr[CAAM_NUM_JOB_RINGS];
	uint8_t				padding[36];
	uint32_t			debugctl;
	uint32_t			jrstartr;
	uint8_t				padding2[4004];
	struct imx_caam_jr_ctrl		jrcfg[CAAM_NUM_JOB_RINGS];
} __packed;

#define MKVB_CL_SIZE	64

struct imx_mkvb {
	struct {
		struct {
			uint32_t desc;
		} inring[8];
		struct {
			uint32_t desc;
			uint32_t status;
		} __packed outring[4];
	} __packed __aligned(MKVB_CL_SIZE) jr;
	uint32_t descriptor[16] __aligned(MKVB_CL_SIZE);
	char outbuf[MKVB_CL_SIZE] __aligned(MKVB_CL_SIZE);
	size_t njobs;
	struct imx_caam_ctrl *ctrl;
};

#endif /* __IMX_CAAM_H__ */
