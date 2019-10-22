/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2019, Huawei Technologies Co., Ltd
 */
#ifndef DL_POLICY_H
#define DL_POLICY_H

#include <tee_api_types.h>

struct dl_policy {
	const TEE_UUID lib_uuid;
	const TEE_UUID *allowed_tas;
};

#define ANY_UUID { 0xffffffff, 0xffff, 0xffff, { 0xff, 0xff, 0xff, 0xff, \
						 0xff, 0xff, 0xff, 0xff } }

extern struct dl_policy dl_policies[];

#endif /* DL_POLICY_H */
