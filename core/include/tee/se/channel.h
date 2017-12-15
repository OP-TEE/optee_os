/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, Linaro Limited
 */

#ifndef TEE_SE_CHANNEL_H
#define TEE_SE_CHANNEL_H

struct tee_se_aid;

/*
 * GP Card API define the maximum logical channel number is 20,
 * Numbered from 0 ~ 19, number 0 is basic logical channel
 */
#define MAX_LOGICAL_CHANNEL	20

struct tee_se_session *tee_se_channel_get_session(struct tee_se_channel *c);

int tee_se_channel_get_id(struct tee_se_channel *c);

TEE_Result tee_se_channel_select_next(struct tee_se_channel *c);

TEE_Result tee_se_channel_select(struct tee_se_channel *c,
		struct tee_se_aid *aid);

void tee_se_channel_set_aid(struct tee_se_channel *c,
		struct tee_se_aid *aid);

void tee_se_channel_set_select_response(struct tee_se_channel *c,
		struct resp_apdu *resp);

TEE_Result tee_se_channel_get_select_response(struct tee_se_channel *c,
		struct resp_apdu **resp);

TEE_Result tee_se_channel_transmit(struct tee_se_channel *c,
		struct cmd_apdu *cmd_apdu, struct resp_apdu *resp_apdu);
#endif
