/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, Linaro Limited
 * All rights reserved.
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
