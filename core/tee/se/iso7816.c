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

#include <tee_api_types.h>
#include <trace.h>
#include <kernel/tee_common_unpg.h>
#include <tee/se/reader.h>
#include <tee/se/session.h>
#include <tee/se/iso7816.h>
#include <tee/se/aid.h>
#include <tee/se/apdu.h>
#include <tee/se/channel.h>
#include <tee/se/util.h>
#include <tee/se/reader/interface.h>

#include <malloc.h>
#include <stdlib.h>
#include <string.h>

enum {
	/* command APDU */
	CLA = 0,
	INS = 1,
	P1 = 2,
	P2 = 3,
	LC = 4,
	CDATA = 5,
	OFF_LE = 0,

	/* response APDU */
	RDATA = 0,
	OFF_SW1 = 0,
	OFF_SW2 = 1,
};

struct apdu_base {
	uint8_t *data_buf;
	size_t length;
	int refcnt;
};

struct cmd_apdu {
	struct apdu_base base;
};

struct resp_apdu {
	struct apdu_base base;
	uint8_t sw1;
	uint8_t sw2;
	uint8_t *resp_data;
	size_t resp_data_len;
};

struct tee_se_aid {
	uint8_t aid[MAX_AID_LENGTH];
	size_t length;
	int refcnt;
};

/*
 * APDU format, [..] means optional fields
 *
 * CMD_APDU: CLA, INS, P1, P2, [LC, DATA, LE]
 * RESP_APDU: [DATA], SW1, SW2
 *
 */
#define CMD_APDU_SIZE(lc) ((lc) + 4)
#define RESP_APDU_SIZE(le) ((le) + 2)

struct cmd_apdu *alloc_cmd_apdu(uint8_t cla, uint8_t ins, uint8_t p1,
		uint8_t p2, uint8_t lc, uint8_t le, uint8_t *data)
{
	size_t apdu_length = CMD_APDU_SIZE(lc);
	size_t total_length;
	struct cmd_apdu *apdu;
	uint8_t *buf;

	/*
	 * check if we need to reserve space for LC/LE
	 * (both fields are optional)
	 */
	if (lc)
		apdu_length++;
	if (le)
		apdu_length++;

	total_length = sizeof(struct cmd_apdu) + apdu_length;
	apdu = malloc(total_length);

	if (!apdu)
		return NULL;

	apdu->base.length = apdu_length;
	apdu->base.data_buf = (uint8_t *)(apdu + 1);
	apdu->base.refcnt = 1;

	buf = apdu->base.data_buf;
	buf[CLA] = cla;
	buf[INS] = ins;
	buf[P1] = p1;
	buf[P2] = p2;
	if (lc)
		buf[LC] = lc;
	if (data != NULL)
		memmove(&buf[CDATA], data, lc);
	if (le)
		buf[CDATA + lc + OFF_LE] = le;

	return apdu;
}

struct cmd_apdu *alloc_cmd_apdu_from_buf(uint8_t *buf, size_t length)
{
	struct cmd_apdu *apdu = malloc(sizeof(struct cmd_apdu));

	if (!apdu)
		return NULL;
	apdu->base.length = length;
	apdu->base.data_buf = buf;
	apdu->base.refcnt = 1;
	return apdu;
}

struct resp_apdu *alloc_resp_apdu(uint8_t le)
{
	size_t total_length = sizeof(struct resp_apdu) + RESP_APDU_SIZE(le);
	struct resp_apdu *apdu;

	apdu = malloc(total_length);

	if (!apdu)
		return NULL;

	apdu->base.length = RESP_APDU_SIZE(le);
	apdu->base.data_buf = (uint8_t *)(apdu + 1);
	apdu->base.refcnt = 1;

	return apdu;
}

uint8_t *resp_apdu_get_data(struct resp_apdu *apdu)
{
	TEE_ASSERT(apdu != NULL);
	return apdu->resp_data;
}

size_t resp_apdu_get_data_len(struct resp_apdu *apdu)
{
	TEE_ASSERT(apdu != NULL);
	return apdu->resp_data_len;
}

uint8_t resp_apdu_get_sw1(struct resp_apdu *apdu)
{
	TEE_ASSERT(apdu != NULL);
	return apdu->sw1;
}

uint8_t resp_apdu_get_sw2(struct resp_apdu *apdu)
{
	TEE_ASSERT(apdu != NULL);
	return apdu->sw2;
}

uint8_t *apdu_get_data(struct apdu_base *apdu)
{
	TEE_ASSERT(apdu != NULL);
	return apdu->data_buf;
}
size_t apdu_get_length(struct apdu_base *apdu)
{
	TEE_ASSERT(apdu != NULL);
	return apdu->length;
}
int apdu_get_refcnt(struct apdu_base *apdu)
{
	TEE_ASSERT(apdu != NULL);
	return apdu->refcnt;
}
void apdu_acquire(struct apdu_base *apdu)
{
	TEE_ASSERT(apdu != NULL);
	apdu->refcnt++;
}
void apdu_release(struct apdu_base *apdu)
{
	TEE_ASSERT(apdu != NULL);
	apdu->refcnt--;
	if (apdu->refcnt == 0)
		free(apdu);
}



TEE_Result tee_se_aid_create(const char *name, struct tee_se_aid **aid)
{
	size_t str_length = strlen(name);
	size_t aid_length = str_length / 2;

	TEE_ASSERT(aid != NULL && *aid == NULL);
	if (str_length < MIN_AID_LENGTH || str_length > MAX_AID_LENGTH)
		return TEE_ERROR_BAD_PARAMETERS;

	*aid = malloc(sizeof(struct tee_se_aid));
	if (!(*aid))
		return TEE_ERROR_OUT_OF_MEMORY;

	hex_decode(name, str_length, (*aid)->aid);
	(*aid)->length = aid_length;
	(*aid)->refcnt = 1;
	return TEE_SUCCESS;
}

TEE_Result tee_se_aid_create_from_buffer(uint8_t *id, size_t length,
		struct tee_se_aid **aid)
{
	*aid = malloc(sizeof(struct tee_se_aid));
	if (!(*aid))
		return TEE_ERROR_OUT_OF_MEMORY;

	memcpy((*aid)->aid, id, length);
	(*aid)->length = length;
	(*aid)->refcnt = 1;
	return TEE_SUCCESS;
}

void tee_se_aid_acquire(struct tee_se_aid *aid)
{
	TEE_ASSERT(aid != NULL);
	aid->refcnt++;
}

int tee_se_aid_get_refcnt(struct tee_se_aid *aid)
{
	TEE_ASSERT(aid != NULL);
	return aid->refcnt;
}

void tee_se_aid_release(struct tee_se_aid *aid)
{
	TEE_ASSERT(aid != NULL && aid->refcnt > 0);
	aid->refcnt--;
	if (aid->refcnt == 0)
		free(aid);
}

static void parse_resp_apdu(struct resp_apdu *apdu)
{
	uint8_t *buf = apdu->base.data_buf;
	/* resp data length =  resp buf length - SW1 - SW2 */
	apdu->resp_data_len = apdu->base.length - 2;
	if (apdu->resp_data_len > 0)
		apdu->resp_data = &buf[RDATA];
	else
		apdu->resp_data = NULL;
	apdu->sw1 = buf[RDATA + apdu->resp_data_len + OFF_SW1];
	apdu->sw2 = buf[RDATA + apdu->resp_data_len + OFF_SW2];
}

TEE_Result iso7816_exchange_apdu(struct tee_se_reader_proxy *proxy,
		struct cmd_apdu *cmd, struct resp_apdu *resp)
{
	TEE_Result ret;

	TEE_ASSERT(cmd != NULL && resp != NULL);
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

	TEE_ASSERT(c != NULL);

	s = tee_se_channel_get_session(c);
	channel_id = tee_se_channel_get_id(c);

	TEE_ASSERT(channel_id < MAX_LOGICAL_CHANNEL);

	cla_channel = iso7816_get_cla_channel(channel_id);
	if (select_ops == FIRST_OR_ONLY_OCCURRENCE) {
		TEE_ASSERT(aid != NULL);
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

	TEE_ASSERT(s != NULL);

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
