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
#include <tee_api_types.h>
#include <trace.h>

#include <tee/se/session.h>
#include <tee/se/channel.h>
#include <tee/se/iso7816.h>
#include <tee/se/aid.h>
#include <tee/se/apdu.h>

#include <stdlib.h>
#include <string.h>

#include "aid_priv.h"
#include "channel_priv.h"

struct tee_se_channel *tee_se_channel_alloc(struct tee_se_session *s,
		int channel_id)
{
	struct tee_se_channel *c;

	c = malloc(sizeof(struct tee_se_channel));
	if (c) {
		c->session = s;
		c->channel_id = channel_id;
		c->aid = NULL;
		c->select_resp = NULL;
	}
	return c;
}

void tee_se_channel_free(struct tee_se_channel *c)
{
	assert(c);
	if (c->aid)
		tee_se_aid_release(c->aid);
	if (c->select_resp)
		apdu_release(to_apdu_base(c->select_resp));
}

struct tee_se_session *tee_se_channel_get_session(struct tee_se_channel *c)
{
	assert(c);
	return c->session;
}

int tee_se_channel_get_id(struct tee_se_channel *c)
{
	assert(c);
	return c->channel_id;
}

void tee_se_channel_set_select_response(struct tee_se_channel *c,
		struct resp_apdu *resp)
{
	assert(c);

	if (c->select_resp)
		apdu_release(to_apdu_base(c->select_resp));
	apdu_acquire(to_apdu_base(resp));
	c->select_resp = resp;
}

TEE_Result tee_se_channel_get_select_response(struct tee_se_channel *c,
		struct resp_apdu **resp)
{
	assert(c && resp);

	if (c->select_resp) {
		*resp = c->select_resp;
		return TEE_SUCCESS;
	} else {
		return TEE_ERROR_NO_DATA;
	}
}

void tee_se_channel_set_aid(struct tee_se_channel *c,
		struct tee_se_aid *aid)
{
	assert(c);
	if (c->aid)
		tee_se_aid_release(c->aid);
	tee_se_aid_acquire(aid);
	c->aid = aid;
}


TEE_Result tee_se_channel_select(struct tee_se_channel *c,
		struct tee_se_aid *aid)
{
	assert(c);
	return iso7816_select(c, aid);
}

TEE_Result tee_se_channel_select_next(struct tee_se_channel *c)
{
	assert(c);
	return iso7816_select_next(c);
}

TEE_Result tee_se_channel_transmit(struct tee_se_channel *c,
		struct cmd_apdu *cmd_apdu, struct resp_apdu *resp_apdu)
{
	struct tee_se_session *s;
	uint8_t *cmd_buf;
	int cla_channel;

	assert(c && cmd_apdu && resp_apdu);

	s = c->session;
	cla_channel = iso7816_get_cla_channel(c->channel_id);
	cmd_buf = apdu_get_data(to_apdu_base(cmd_apdu));
	cmd_buf[ISO7816_CLA_OFFSET] = ISO7816_CLA | cla_channel;
	return tee_se_session_transmit(s, cmd_apdu, resp_apdu);
}
