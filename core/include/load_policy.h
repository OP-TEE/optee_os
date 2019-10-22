/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2019, Huawei Technologies Co., Ltd
 */
#ifndef LOAD_POLICY_H
#define LOAD_POLICY_H

#include <tee_api_types.h>

struct load_policy {
	const TEE_UUID ta_uuid;
	const char *tag;
	const size_t tag_len;
	const TEE_UUID *allowed_libs;
};

#define ANY_UUID { 0xffffffff, 0xffff, 0xffff, { 0xff, 0xff, 0xff, 0xff, \
						 0xff, 0xff, 0xff, 0xff } }

extern const struct load_policy load_policies[];

#endif /* DL_POLICY_H */
