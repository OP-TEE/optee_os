// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2020, Open Mobile Platform LLC
 */

#include <assert.h>
#include <kernel/thread.h>
#include <mm/mobj.h>
#include <optee_rpc_cmd.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <tee/tee_supp_plugin_rpc.h>
#include <tee/uuid.h>
#include <trace.h>

TEE_Result tee_invoke_supp_plugin_rpc(const TEE_UUID *uuid, uint32_t cmd,
				      uint32_t sub_cmd, void *buf, size_t len,
				      size_t *outlen)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct thread_param params[THREAD_RPC_MAX_NUM_PARAMS];
	uint32_t uuid_words[4] = { };
	void *va = NULL;
	struct mobj *mobj = NULL;

	/*
	 * sizeof 'TEE_UUID' and array 'uuid_words' must be same size,
	 * because 'tee_uuid_to_octets()' is used to copy variable
	 * with one type to another.
	 *
	 * Array 'uuid_words' is used just for convenient work with
	 * 'TEE_UUID' as with uint32_t values.
	 */
	COMPILE_TIME_ASSERT(sizeof(TEE_UUID) == sizeof(uuid_words));

	if (!uuid || (len && !buf) || (!len && buf))
		return TEE_ERROR_BAD_PARAMETERS;

	if (len) {
		mobj = thread_rpc_alloc_payload(len);
		if (!mobj) {
			EMSG("can't create mobj for plugin data");
			return TEE_ERROR_OUT_OF_MEMORY;
		}

		va = mobj_get_va(mobj, 0);
		if (!va) {
			EMSG("can't get va from mobj");
			goto out;
		}

		memcpy(va, buf, len);
	}

	tee_uuid_to_octets((uint8_t *)uuid_words, uuid);

	params[0] = THREAD_PARAM_VALUE(IN, OPTEE_RPC_SUPP_PLUGIN_INVOKE,
				       uuid_words[0], uuid_words[1]);
	params[1] = THREAD_PARAM_VALUE(IN, uuid_words[2], uuid_words[3], cmd);
	params[2] = THREAD_PARAM_VALUE(INOUT, sub_cmd, 0, 0);
	params[3] = THREAD_PARAM_MEMREF(INOUT, mobj, 0, len);

	res = thread_rpc_cmd(OPTEE_RPC_CMD_SUPP_PLUGIN, 4, params);

	if (outlen)
		*outlen = params[2].u.value.b;

	if (len && outlen && *outlen)
		memcpy(buf, va, *outlen <= len ? *outlen : len);

out:
	if (len)
		thread_rpc_free_payload(mobj);

	return res;
}
