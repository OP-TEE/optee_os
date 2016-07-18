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

#include <assert.h>
#include <kernel/mutex.h>
#include <stdlib.h>
#include <sys/queue.h>
#include <trace.h>

#include <tee/se/reader.h>
#include <tee/se/session.h>
#include <tee/se/channel.h>
#include <tee/se/iso7816.h>

#include "session_priv.h"
#include "channel_priv.h"

struct tee_se_session *tee_se_session_alloc(
		struct tee_se_reader_proxy *proxy)
{
	struct tee_se_session *s;

	assert(proxy);
	s = malloc(sizeof(struct tee_se_session));
	if (s) {
		TAILQ_INIT(&s->channels);
		s->reader_proxy = proxy;
	}
	return s;
}

void tee_se_session_free(struct tee_se_session *s)
{
	free(s);
}

bool tee_se_session_is_channel_exist(struct tee_se_session *s,
		struct tee_se_channel *c)
{
	struct tee_se_channel *c1;

	TAILQ_FOREACH(c1, &s->channels, link) {
		if (c1 == c)
			return true;
	}
	return false;
}

TEE_Result tee_se_session_get_atr(struct tee_se_session *s,
		uint8_t **atr, size_t *atr_len)
{
	assert(s && atr && atr_len);

	return tee_se_reader_get_atr(s->reader_proxy, atr, atr_len);
}

TEE_Result tee_se_session_open_basic_channel(struct tee_se_session *s,
		struct tee_se_aid *aid, struct tee_se_channel **channel)
{
	struct tee_se_channel *c;
	TEE_Result ret;

	assert(s && channel && !*channel);

	if (tee_se_reader_is_basic_channel_locked(s->reader_proxy)) {
		*channel = NULL;
		return TEE_ERROR_NOT_SUPPORTED;
	}

	c = tee_se_channel_alloc(s, 0);
	if (!c)
		return TEE_ERROR_OUT_OF_MEMORY;

	if (aid) {
		ret = iso7816_select(c, aid);
		if (ret != TEE_SUCCESS)
			goto err_free_channel;
	}

	tee_se_reader_lock_basic_channel(s->reader_proxy);
	*channel = c;
	TAILQ_INSERT_TAIL(&s->channels, c, link);

	return TEE_SUCCESS;

err_free_channel:
	tee_se_channel_free(c);
	return ret;
}

TEE_Result tee_se_session_open_logical_channel(struct tee_se_session *s,
		struct tee_se_aid *aid, struct tee_se_channel **channel)
{
	int channel_id;
	struct tee_se_channel *c;
	TEE_Result ret;

	assert(s && channel && !*channel);

	ret = iso7816_open_available_logical_channel(s, &channel_id);
	if (ret != TEE_SUCCESS)
		return ret;

	c = tee_se_channel_alloc(s, channel_id);
	if (!c)
		goto err_close_channel;

	if (aid != NULL) {
		ret = iso7816_select(c, aid);
		if (ret != TEE_SUCCESS)
			goto err_free_channel;
	}

	*channel = c;
	TAILQ_INSERT_TAIL(&s->channels, c, link);

	return TEE_SUCCESS;

err_free_channel:
	tee_se_channel_free(c);
err_close_channel:
	iso7816_close_logical_channel(s, channel_id);

	return ret;
}

void tee_se_session_close_channel(struct tee_se_session *s,
		struct tee_se_channel *c)
{
	int channel_id;

	assert(s && c);
	channel_id = tee_se_channel_get_id(c);
	if (channel_id > 0) {
		iso7816_close_logical_channel(s, channel_id);
	} else {
		tee_se_reader_unlock_basic_channel(s->reader_proxy);
	}

	TAILQ_REMOVE(&s->channels, c, link);
	tee_se_channel_free(c);
}

TEE_Result tee_se_session_transmit(struct tee_se_session *s,
		struct cmd_apdu *c, struct resp_apdu *r)
{
	struct tee_se_reader_proxy *h = s->reader_proxy;

	/*
	 * This call might block the caller.
	 * The reader proxy will make sure only 1 session
	 * is transmitting. Others should wait until the
	 * activating transation finished.
	 */
	return iso7816_exchange_apdu(h, c, r);
}

void tee_se_session_close(struct tee_se_session *s)
{
	struct tee_se_channel *c;

	assert(s);

	TAILQ_FOREACH(c, &s->channels, link)
		tee_se_session_close_channel(s, c);

	tee_se_reader_detach(s->reader_proxy);

	tee_se_session_free(s);
}
