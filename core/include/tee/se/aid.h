/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, Linaro Limited
 */
#ifndef TEE_SE_AID
#define TEE_SE_AID

#define MAX_AID_LENGTH	16
#define MIN_AID_LENGTH	5

struct tee_se_aid;

TEE_Result tee_se_aid_create_from_buffer(uint8_t *id, size_t length,
		struct tee_se_aid **aid);

void tee_se_aid_release(struct tee_se_aid *aid);

#endif
