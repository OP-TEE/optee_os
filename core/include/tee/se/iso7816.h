/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, Linaro Limited
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

