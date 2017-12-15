/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 */

#ifndef TEE_SE_READER_PRIV_H
#define TEE_SE_READER_PRIV_H

/*
 * Reader Proxy is used to serialize access from multiple seesions,
 * and maintain reference counter. All access to the reader should
 * go through Reader Proxy
 */
struct tee_se_reader_proxy {
	struct tee_se_reader *reader;
	int refcnt;
	bool basic_channel_locked;
	struct mutex mutex;

	TAILQ_ENTRY(tee_se_reader_proxy) link;
};

TEE_Result tee_se_reader_check_state(struct tee_se_reader_proxy *proxy);

int tee_se_reader_get_refcnt(struct tee_se_reader_proxy *proxy);

#endif
