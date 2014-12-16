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
