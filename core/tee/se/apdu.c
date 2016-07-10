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
#include <stdlib.h>
#include <string.h>
#include <tee_api_types.h>
#include <trace.h>

#include <tee/se/apdu.h>
#include <tee/se/util.h>

#include "apdu_priv.h"

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
	assert(apdu);
	return apdu->resp_data;
}

size_t resp_apdu_get_data_len(struct resp_apdu *apdu)
{
	assert(apdu);
	return apdu->resp_data_len;
}

uint8_t resp_apdu_get_sw1(struct resp_apdu *apdu)
{
	assert(apdu);
	return apdu->sw1;
}

uint8_t resp_apdu_get_sw2(struct resp_apdu *apdu)
{
	assert(apdu);
	return apdu->sw2;
}

uint8_t *apdu_get_data(struct apdu_base *apdu)
{
	assert(apdu);
	return apdu->data_buf;
}
size_t apdu_get_length(struct apdu_base *apdu)
{
	assert(apdu);
	return apdu->length;
}
int apdu_get_refcnt(struct apdu_base *apdu)
{
	assert(apdu);
	return apdu->refcnt;
}
void apdu_acquire(struct apdu_base *apdu)
{
	assert(apdu);
	apdu->refcnt++;
}
void apdu_release(struct apdu_base *apdu)
{
	assert(apdu);
	apdu->refcnt--;
	if (apdu->refcnt == 0)
		free(apdu);
}

void parse_resp_apdu(struct resp_apdu *apdu)
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
