// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2021, Foundries.io Ltd
 */

#include <compiler.h>
#include <crypto/crypto.h>
#include <kernel/tee_random_ree.h>
#include <kernel/thread.h>
#include <optee_rpc_cmd.h>

TEE_Result tee_random_add_ree_random(enum crypto_rng_src sid,
				     unsigned int *pnum)
{
	struct thread_param params = THREAD_PARAM_VALUE(OUT, 0, 0, 0);
	TEE_Result res = TEE_SUCCESS;

	res = thread_rpc_cmd(OPTEE_RPC_CMD_GET_RANDOM, 1, &params);
	if (res != TEE_SUCCESS)
		return res;

	crypto_rng_add_event(sid, pnum,
			     (const void *)&params.u.value,
			     sizeof(params.u.value));

	return TEE_SUCCESS;
}
