// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2016 Freescale Semiconductor, Inc.
 * All rights reserved.
 *
 * Peng Fan <peng.fan@nxp.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdint.h>
#include <sm/optee_smc.h>
#include <sm/psci.h>
#include <sm/sm.h>
#include <sm/std_smc.h>
#include <tee/uuid.h>
#include <trace.h>

static const TEE_UUID uuid = {
	0x5f8b97df, 0x2d0d, 0x4ad2,
	{0x98, 0xd2, 0x74, 0xf4, 0x38, 0x27, 0x98, 0xbb},
};

void smc_std_handler(struct thread_smc_args *args, struct sm_nsec_ctx *nsec)
{
	uint32_t smc_fid = args->a0;

	if (is_psci_fid(smc_fid)) {
		tee_psci_handler(args, nsec);
		return;
	}

	switch (smc_fid) {
	case ARM_STD_SVC_CALL_COUNT:
		/* PSCI is the only STD service implemented */
		args->a0 = PSCI_NUM_CALLS;
		break;
	case ARM_STD_SVC_UID:
		args->a0 = uuid.timeLow;
		args->a1 = (uuid.timeHiAndVersion << 16) | uuid.timeMid;
		args->a2 = (uuid.clockSeqAndNode[3] << 24) |
			(uuid.clockSeqAndNode[2] << 16) |
			(uuid.clockSeqAndNode[1] << 8) |
			uuid.clockSeqAndNode[0];
		args->a3 = (uuid.clockSeqAndNode[7] << 24) |
			(uuid.clockSeqAndNode[6] << 16) |
			(uuid.clockSeqAndNode[5] << 8) |
			uuid.clockSeqAndNode[4];
		break;
	case ARM_STD_SVC_VERSION:
		args->a0 = STD_SVC_VERSION_MAJOR;
		args->a1 = STD_SVC_VERSION_MINOR;
		break;
	default:
		args->a0 = OPTEE_SMC_RETURN_UNKNOWN_FUNCTION;
		break;
	}
}
