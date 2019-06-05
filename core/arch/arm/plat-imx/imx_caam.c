// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2019 Bryan O'Donoghue
 *
 * Bryan O'Donoghue <bryan.odonoghue@linaro.org>
 */

#include <io.h>
#include <imx_caam.h>
#include <kernel/generic_boot.h>
#include <platform_config.h>
#include <stdint.h>

void init_caam(void)
{
	struct imx_caam_ctrl *caam = (struct imx_caam_ctrl *)(vaddr_t)CAAM_BASE;
	uint32_t reg;
	int i;

	/*
	 * Set job-ring ownership to non-secure by default.
	 * A Linux kernel that runs after OP-TEE will run in normal-world
	 * so we want to enable that kernel to have total ownership of the
	 * CAAM job-rings.
	 *
	 * It is possible to use CAAM job-rings inside of OP-TEE i.e. in
	 * secure world code but, to do that OP-TEE and kernel should agree
	 * via a DTB which job-rings are owned by OP-TEE and which are
	 * owned by Kernel, something that the OP-TEE CAAM driver should
	 * set up.
	 *
	 * This code below simply sets a default for the case where no
	 * runtime OP-TEE CAAM code will be run
	 */
	for (i = 0; i < CAAM_NUM_JOB_RINGS; i++) {
		reg = io_read32((vaddr_t)&caam->jr[i].jrmidr_ms);
		reg |= JROWN_NS | JROWN_MID;
		io_write32((vaddr_t)&caam->jr[i].jrmidr_ms, reg);
	}
}
