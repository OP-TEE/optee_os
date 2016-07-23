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
#include <kernel/panic.h>
#include <malloc.h>
#include <stdlib.h>
#include <string.h>
#include <tee_api_types.h>
#include <tee/se/reader.h>
#include <tee/se/session.h>
#include <tee/se/iso7816.h>
#include <tee/se/aid.h>
#include <tee/se/apdu.h>
#include <tee/se/channel.h>
#include <tee/se/util.h>
#include <tee/se/reader/interface.h>
#include <trace.h>

#include "session_priv.h"
#include "aid_priv.h"
#include "apdu_priv.h"

TEE_Result iso7816_exchange_apdu(struct tee_se_reader_proxy *proxy,
		struct cmd_apdu *cmd, struct resp_apdu *resp)
{
	TEE_Result ret;

	assert(cmd && resp);
	ret = tee_se_reader_transmit(proxy,
			cmd->base.data_buf, cmd->base.length,
			resp->base.data_buf, &resp->base.length);

	if (ret == TEE_SUCCESS)
		parse_resp_apdu(resp);

	return ret;
}

int iso7816_get_cla_channel(int channel_id)
{
	int cla_channel;
	/*
	 * From GP Card Spec,
	 * the logical channel number 0~3 should have CLA: 0x00 ~ 0x03,
	 * for channel number 4~19 should have CLA: 0x40 ~ 0x4f
	 */
	if (channel_id < 4)
		cla_channel = channel_id;
	else
		cla_channel = 0x40 | (channel_id - 4);

	return cla_channel;
}

static TEE_Result internal_select(struct tee_se_channel *c,
		struct tee_se_aid *aid, int select_ops)
{
	struct cmd_apdu *cmd;
	struct resp_apdu *resp;
	struct tee_se_session *s;
	TEE_Result ret;
	TEE_SEReaderProperties prop;
	size_t rx_buf_len = 0;
	int channel_id;
	uint8_t cla_channel;

	assert(c);

	s = tee_se_channel_get_session(c);
	channel_id = tee_se_channel_get_id(c);

	if (channel_id >= MAX_LOGICAL_CHANNEL)
		panic("invalid channel id");

	cla_channel = iso7816_get_cla_channel(channel_id);
	if (select_ops == FIRST_OR_ONLY_OCCURRENCE) {
		assert(aid);
		cmd = alloc_cmd_apdu(ISO7816_CLA | cla_channel,
				SELECT_CMD, SELECT_BY_AID,
				select_ops, aid->length,
				rx_buf_len, aid->aid);
	} else {
		cmd = alloc_cmd_apdu(ISO7816_CLA | cla_channel,
				SELECT_CMD, SELECT_BY_AID,
				select_ops, 0, rx_buf_len, NULL);
	}

	resp = alloc_resp_apdu(rx_buf_len);

	ret = tee_se_session_transmit(s, cmd, resp);
	if (ret != TEE_SUCCESS) {
		EMSG("exchange apdu failed: %d", ret);
		return ret;
	}

	tee_se_reader_get_properties(s->reader_proxy, &prop);
	if (prop.selectResponseEnable)
		tee_se_channel_set_select_response(c, resp);
	if (aid)
		tee_se_channel_set_aid(c, aid);

	if (resp->sw1 == CMD_OK_SW1 && resp->sw2 == CMD_OK_SW2) {
		ret = TEE_SUCCESS;
	} else {
		EMSG("operation failed, sw1:%02X, sw2:%02X",
				resp->sw1, resp->sw2);
		if (resp->sw1 == 0x6A && resp->sw2 == 0x83)
			ret = TEE_ERROR_ITEM_NOT_FOUND;
		else
			ret = TEE_ERROR_NOT_SUPPORTED;
	}

	apdu_release(to_apdu_base(cmd));
	apdu_release(to_apdu_base(resp));

	return ret;
}

static TEE_Result internal_manage_channel(struct tee_se_session *s,
		bool open_ops, int *channel_id)
{
	struct cmd_apdu *cmd;
	struct resp_apdu *resp;
	TEE_Result ret;
	size_t tx_buf_len = 0, rx_buf_len = 1;

	uint8_t open_flag = (open_ops) ? OPEN_CHANNEL : CLOSE_CHANNEL;
	uint8_t channel_flag =
		(open_flag == OPEN_CHANNEL) ? OPEN_NEXT_AVAILABLE : *channel_id;

	assert(s);

	cmd = alloc_cmd_apdu(ISO7816_CLA, MANAGE_CHANNEL_CMD, open_flag,
			channel_flag, tx_buf_len, rx_buf_len, NULL);

	resp = alloc_resp_apdu(rx_buf_len);

	ret = tee_se_session_transmit(s, cmd, resp);
	if (ret != TEE_SUCCESS) {
		EMSG("exchange apdu failed: %d", ret);
		return ret;
	}

	if (resp->sw1 == CMD_OK_SW1 && resp->sw2 == CMD_OK_SW2) {
		if (open_ops)
			*channel_id = resp->base.data_buf[0];
		ret = TEE_SUCCESS;
	} else {
		EMSG("operation failed, sw1:%02X, sw2:%02X",
				resp->sw1, resp->sw2);
		ret = TEE_ERROR_NOT_SUPPORTED;
	}

	apdu_release(to_apdu_base(cmd));
	apdu_release(to_apdu_base(resp));

	return ret;
}

TEE_Result iso7816_open_available_logical_channel(struct tee_se_session *s,
		int *channel_id)
{
	return internal_manage_channel(s, true, channel_id);
}

TEE_Result iso7816_close_logical_channel(struct tee_se_session *s,
		int channel_id)
{
	return internal_manage_channel(s, false, &channel_id);
}

TEE_Result iso7816_select(struct tee_se_channel *c, struct tee_se_aid *aid)
{
	return internal_select(c, aid, FIRST_OR_ONLY_OCCURRENCE);
}

TEE_Result iso7816_select_next(struct tee_se_channel *c)
{
	return internal_select(c, NULL, NEXT_OCCURRENCE);
}
