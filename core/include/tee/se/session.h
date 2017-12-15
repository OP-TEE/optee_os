/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, Linaro Limited
 */

#ifndef TEE_SE_SESSION_H
#define TEE_SE_SESSION_H

#include <tee_api_types.h>
#include <kernel/mutex.h>

#include <sys/queue.h>

struct tee_se_reader_proxy;
struct tee_se_channel;
struct tee_se_session;
struct tee_se_aid;
struct cmd_apdu;
struct resp_apdu;

TEE_Result tee_se_session_open_basic_channel(struct tee_se_session *s,
		struct tee_se_aid *aid, struct tee_se_channel **channel);

TEE_Result tee_se_session_open_logical_channel(struct tee_se_session *s,
		struct tee_se_aid *aid, struct tee_se_channel **channel);

bool tee_se_session_is_channel_exist(struct tee_se_session *s,
		struct tee_se_channel *c);

void tee_se_session_close_channel(struct tee_se_session *s,
		struct tee_se_channel *c);

TEE_Result tee_se_session_get_atr(struct tee_se_session *s,
		uint8_t **atr, size_t *atr_len);

TEE_Result tee_se_session_transmit(struct tee_se_session *s,
		struct cmd_apdu *c, struct resp_apdu *r);

void tee_se_session_close(struct tee_se_session *s);

#endif
