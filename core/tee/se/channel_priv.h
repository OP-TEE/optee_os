/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, Linaro Limited
 */

#ifndef TEE_SE_CHANNEL_PRIV_H
#define TEE_SE_CHANNEL_PRIV_H

struct tee_se_aid;

struct tee_se_channel {
	int channel_id;
	struct tee_se_session *session;
	struct tee_se_aid *aid;
	struct resp_apdu *select_resp;

	TAILQ_ENTRY(tee_se_channel) link;
};

struct tee_se_channel *tee_se_channel_alloc(struct tee_se_session *s,
		int channel_id);

void tee_se_channel_free(struct tee_se_channel *c);

#endif
