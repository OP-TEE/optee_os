/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, Linaro Limited
 */

#ifndef TEE_SE_AID_PRIV_H
#define TEE_SE_AID_PRIV_H

struct tee_se_aid {
	uint8_t aid[MAX_AID_LENGTH];
	size_t length;
	int refcnt;
};

int tee_se_aid_get_refcnt(struct tee_se_aid *aid);

TEE_Result tee_se_aid_create(const char *name, struct tee_se_aid **aid);

void tee_se_aid_acquire(struct tee_se_aid *aid);

#endif
