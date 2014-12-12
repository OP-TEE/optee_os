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

#ifndef TEE_SE_PROTOCOL_H
#define TEE_SE_PROTOCOL_H

#define ISO7816_CLA	0x0

#define ISO7816_CLA_OFFSET	0x0

#define SELECT_CMD			0xA4
/* P1 parameters */
#define	SELECT_BY_AID			0x04
/* P2 parameters */
#define	FIRST_OR_ONLY_OCCURRENCE	0x0
#define	NEXT_OCCURRENCE			0x2

#define MANAGE_CHANNEL_CMD		0x70
/* P1 parameters */
#define	OPEN_CHANNEL			0x00
#define	CLOSE_CHANNEL			0x80
/* P2 parameters */
#define	OPEN_NEXT_AVAILABLE		0x00


#define CMD_OK_SW1	0x90
#define CMD_OK_SW2	0x00

struct tee_se_reader_proxy;
struct tee_se_session;
struct tee_se_channel;
struct tee_se_aid;
struct cmd_apdu;
struct resp_apdu;

/* ISO7816 protocol handlers */
TEE_Result iso7816_exchange_apdu(struct tee_se_reader_proxy *proxy,
		struct cmd_apdu *cmd, struct resp_apdu *resp);

TEE_Result iso7816_select(struct tee_se_channel *c, struct tee_se_aid *aid);

TEE_Result iso7816_select_next(struct tee_se_channel *c);

TEE_Result iso7816_open_available_logical_channel(struct tee_se_session *s,
		int *channel_id);

TEE_Result iso7816_close_logical_channel(struct tee_se_session *s,
		int channel_id);

int iso7816_get_cla_channel(int channel_id);


#endif

