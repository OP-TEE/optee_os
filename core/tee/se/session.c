/*
 * Copyright (c) 2014, Linaro Limited
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

#include <trace.h>
#include <kernel/tee_ta_manager_unpg.h>
#include <kernel/tee_common_unpg.h>
#include <kernel/mutex.h>

#include <tee/se/reader.h>
#include <tee/se/session.h>
#include <tee/se/channel.h>
#include <tee/se/protocol.h>

#include <stdlib.h>
#include <sys/queue.h>

TAILQ_HEAD(channel_list, tee_se_channel);

struct tee_se_session {

	TAILQ_ENTRY(tee_se_session) link;

	struct tee_se_reader_handle *handle;

	/* list of channels opened on the session*/
	struct channel_list channels;
};

struct tee_se_session *alloc_tee_se_session(struct tee_se_reader_handle *handle)
{
	struct tee_se_session *s;
	TEE_ASSERT(handle != NULL);

	s = malloc(sizeof(struct tee_se_session));
	if (s) {
		TAILQ_INIT(&s->channels);
		s->handle = handle;
	}
	return s;
}

void free_tee_se_session(struct tee_se_session *s) {
	free(s);
}

void add_tee_se_session(struct tee_ta_ctx *ctx, struct tee_se_session *s)
{
	TAILQ_INSERT_TAIL(&ctx->se_sessions, s, link);
}

void remove_tee_se_session(struct tee_ta_ctx *ctx, struct tee_se_session *s)
{
	TAILQ_REMOVE(&ctx->se_sessions, s, link);
}


TEE_Result tee_se_session_open_basic_channel(struct tee_se_session *s,
		struct tee_se_aid *aid, struct tee_se_channel **channel)
{
	struct tee_se_reader_handle *handle;
	struct tee_se_channel *c;
	TEE_Result ret;

	TEE_ASSERT(s != NULL && channel != NULL && *channel == NULL);

	handle = tee_se_session_get_reader_handle(s);

	if (tee_se_reader_is_basic_channel_locked(handle)) {
		*channel = NULL;
		return TEE_ERROR_NOT_SUPPORTED;
	}

	c = alloc_tee_se_channel(s, 0);
	if (!c)
		return TEE_ERROR_OUT_OF_MEMORY;

	if (aid) {
		ret = iso7816_select(c, aid);
		if (ret != TEE_SUCCESS)
			goto err_free_channel;
	}

	tee_se_reader_lock_basic_channel(handle);
	*channel = c;

	return TEE_SUCCESS;

err_free_channel:
	free_tee_se_channel(c);
	return ret;
}

TEE_Result tee_se_session_open_logical_channel(struct tee_se_session *s,
		struct tee_se_aid *aid, struct tee_se_channel **channel)
{
	int channel_id;
	struct tee_se_channel *c;
	TEE_Result ret;

	TEE_ASSERT(s != NULL && channel != NULL && *channel == NULL);

	ret = iso7816_open_available_logical_channel(s, &channel_id);
	if (ret != TEE_SUCCESS)
		return ret;

	c = alloc_tee_se_channel(s, channel_id);
	if (!c)
		goto err_close_channel;

	if (aid != NULL) {
		ret = iso7816_select(c, aid);
		if (ret != TEE_SUCCESS)
			goto err_free_channel;
	}

	*channel = c;

	return TEE_SUCCESS;

err_free_channel:
	free_tee_se_channel(c);
err_close_channel:
	iso7816_close_logical_channel(s, channel_id);

	return ret;
}

void tee_se_session_close_channel(struct tee_se_session *s,
		struct tee_se_channel *c)
{
	int channel_id;

	TEE_ASSERT(s != NULL && c != NULL);
	channel_id = tee_se_channel_get_id(c);
	if (channel_id > 0) {
		iso7816_close_logical_channel(s, channel_id);
	} else {
		struct tee_se_reader_handle *handle;

		handle = tee_se_session_get_reader_handle(s);
		tee_se_reader_unlock_basic_channel(handle);
	}
	free_tee_se_channel(c);
}

TEE_Result tee_se_session_transmit(struct tee_se_session *session,
		struct cmd_apdu *c, struct resp_apdu *r)
{
	struct tee_se_reader_handle *h = session->handle;

	/*
	 * This call might block the caller.
	 * The reader handle will make sure only 1 session
	 * is transmitting. Others should wait until the
	 * activating transation finished.
	 */
	return iso7816_exchange_apdu(h, c, r);
}

struct tee_se_reader_handle *tee_se_session_get_reader_handle(
		struct tee_se_session *session)
{
	return session->handle;
}
