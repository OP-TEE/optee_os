/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, Linaro Limited
 */

#ifndef TEE_SE_MANAGER_H
#define TEE_SE_MANAGER_H

#include <tee_api_types.h>

struct tee_se_reader_proxy;

TEE_Result tee_se_manager_get_readers(
		struct tee_se_reader_proxy **proxy_list,
		size_t *proxy_list_size);

bool tee_se_manager_is_reader_proxy_valid(
		struct tee_se_reader_proxy *proxy);

size_t tee_se_manager_get_reader_count(void);

#endif
