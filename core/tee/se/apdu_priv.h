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

#ifndef TEE_SE_APDU_PRIV_H
#define TEE_SE_APDU_PRIV_H

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

void parse_resp_apdu(struct resp_apdu *apdu);

int apdu_get_refcnt(struct apdu_base *apdu);

#endif
