/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 */
#ifndef TEE_SE_APDU
#define TEE_SE_APDU

struct cmd_apdu;
struct resp_apdu;
struct apdu_base;

#define to_apdu_base(apdu)	((struct apdu_base *)(apdu))

struct cmd_apdu *alloc_cmd_apdu(uint8_t cla, uint8_t ins, uint8_t p1,
		uint8_t p2, uint8_t lc, uint8_t le, uint8_t *data);

struct cmd_apdu *alloc_cmd_apdu_from_buf(uint8_t *buf, size_t length);

struct resp_apdu *alloc_resp_apdu(uint8_t le);

uint8_t *resp_apdu_get_data(struct resp_apdu *apdu);

size_t resp_apdu_get_data_len(struct resp_apdu *apdu);

uint8_t resp_apdu_get_sw1(struct resp_apdu *apdu);

uint8_t resp_apdu_get_sw2(struct resp_apdu *apdu);

uint8_t *apdu_get_data(struct apdu_base *apdu);

size_t apdu_get_length(struct apdu_base *apdu);

void apdu_acquire(struct apdu_base *apdu);

void apdu_release(struct apdu_base *apdu);


#endif
