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
