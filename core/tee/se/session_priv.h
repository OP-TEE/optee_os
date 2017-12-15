/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 */

#ifndef TEE_SE_SESSION_PRIV_H
#define TEE_SE_SESSION_PRIV_H

TAILQ_HEAD(channel_list, tee_se_channel);

struct tee_se_session {
	struct tee_se_reader_proxy *reader_proxy;

	/* list of channels opened on the session*/
	struct channel_list channels;

	TAILQ_ENTRY(tee_se_session) link;
};

struct tee_se_session *tee_se_session_alloc(struct tee_se_reader_proxy *proxy);

void tee_se_session_free(struct tee_se_session *s);

#endif
