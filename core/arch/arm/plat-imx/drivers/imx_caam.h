/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2019 Bryan O'Donoghue
 * Copyright 2019 NXP
 *
 * Bryan O'Donoghue <bryan.odonoghue@linaro.org>
 */

#ifndef __IMX_CAAM_H__
#define __IMX_CAAM_H__

#include <imx-regs.h>
#include <stdint.h>

struct imx_caam_job_ring {
	uint32_t			jrmidr_ms;
	uint32_t			jrmidr_ls;
};

#define CAAM_NUM_JOB_RINGS		4

/* CAAM ownersip definition bits */
#define JROWN_NS			BIT(3)
#define JROWN_MID			0x01

/* A basic sub-set of the CAAM */
struct imx_caam_ctrl {
	uint32_t			res0;
	uint32_t			mcfgr;
	uint32_t			res1;
	uint32_t			scfgr;
	struct imx_caam_job_ring	jr[CAAM_NUM_JOB_RINGS];
};

#endif /* __IMX_CAAM_H__ */
