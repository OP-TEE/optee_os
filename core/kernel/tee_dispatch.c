/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * All rights reserved.
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

#include <kernel/tee_dispatch.h>
#include <kernel/tee_ta_manager.h>
#include <kernel/tee_time.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <string.h>
#include <tee/tee_cryp_utl.h>
#include <string.h>

/* Sessions opened from normal world */
static struct tee_ta_session_head tee_open_sessions =
TAILQ_HEAD_INITIALIZER(tee_open_sessions);

static TEE_Result update_clnt_id(const TEE_Identity *in, TEE_Identity *out)
{
	/*
	 * Check that only login types from normal world are allowed.
	 */
	out->login = in->login;
	switch (out->login) {
	case TEE_LOGIN_PUBLIC:
		memset(&out->uuid, 0, sizeof(TEE_UUID));
		break;
	case TEE_LOGIN_USER:
	case TEE_LOGIN_GROUP:
	case TEE_LOGIN_APPLICATION:
	case TEE_LOGIN_APPLICATION_USER:
	case TEE_LOGIN_APPLICATION_GROUP:
		out->uuid = in->uuid;
		break;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
	return TEE_SUCCESS;
}

static void inject_entropy_with_timestamp(void)
{
	TEE_Time current;

	if (tee_time_get_sys_time(&current) == TEE_SUCCESS)
		tee_prng_add_entropy((uint8_t *)&current, sizeof(current));
}

TEE_Result tee_dispatch_open_session(struct tee_dispatch_open_session_in *in,
				     struct tee_dispatch_open_session_out *out)
{
	TEE_Result res = TEE_ERROR_BAD_PARAMETERS;
	struct tee_ta_session *s = NULL;
	uint32_t res_orig = TEE_ORIGIN_TEE;
	TEE_Identity clnt_id;

	/* copy client info in a safe place */
	res = update_clnt_id(&in->clnt_id, &clnt_id);
	if (res != TEE_SUCCESS)
		goto cleanup_return;

	out->param = in->param;
	res = tee_ta_open_session(&res_orig, &s, &tee_open_sessions, &in->uuid,
				  &clnt_id, TEE_TIMEOUT_INFINITE, &out->param);
	if (res != TEE_SUCCESS)
		goto cleanup_return;

	out->sess = (TEE_Session *)s;

	/*
	 * The occurrence of open/close session command is usually
	 * un-predictable, using this property to increase randomness
	 * of prng
	 */
	inject_entropy_with_timestamp();

cleanup_return:
	if (res != TEE_SUCCESS)
		DMSG("  => Error: %x of %d", (unsigned int)res, (int)res_orig);

	out->msg.err = res_orig;
	out->msg.res = res;
	return res;
}

TEE_Result tee_dispatch_close_session(struct tee_close_session_in *in)
{
	inject_entropy_with_timestamp();

	return tee_ta_close_session((struct tee_ta_session *)in->sess,
				    &tee_open_sessions, NSAPP_IDENTITY);
}

TEE_Result tee_dispatch_invoke_command(struct tee_dispatch_invoke_command_in *
				       in,
				       struct tee_dispatch_invoke_command_out *
				       out)
{
	struct tee_ta_session *sess;
	TEE_Result res;
	TEE_ErrorOrigin err = TEE_ORIGIN_TEE;

	sess = tee_ta_get_session((vaddr_t)in->sess, true, &tee_open_sessions);
	if (!sess) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto cleanup_return;
	}

	out->param = in->param;
	res = tee_ta_invoke_command(&err, sess, NSAPP_IDENTITY,
				    TEE_TIMEOUT_INFINITE, in->cmd, &out->param);

	tee_ta_put_session(sess);


cleanup_return:
	out->msg.res = res;
	out->msg.err = err;
	return out->msg.res;
}

TEE_Result tee_dispatch_cancel_command(struct tee_dispatch_cancel_command_in *
				       in,
				       struct tee_dispatch_cancel_command_out *
				       out)
{
	TEE_Result res = TEE_ERROR_BAD_PARAMETERS;
	struct tee_ta_session *sess = (struct tee_ta_session *)in->sess;
	uint32_t res_orig = TEE_ORIGIN_TEE;

	sess = tee_ta_get_session((vaddr_t)in->sess, false, &tee_open_sessions);
	if (!sess) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto cleanup_return;
	}

	res = tee_ta_cancel_command(&res_orig, sess, NSAPP_IDENTITY);

	tee_ta_put_session(sess);

cleanup_return:
	out->msg.err = res_orig;
	out->msg.res = res;
	return res;
}
