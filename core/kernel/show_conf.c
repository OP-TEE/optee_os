// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 1019 Huawei Technologies Co., Ltd
 */

#include <initcall.h>
#include <trace.h>

extern const char conf_str[];

static TEE_Result show_conf(void)
{
#if (TRACE_LEVEL >= TRACE_INFO)
	IMSG("Contents of conf.mk (decode with 'base64 -d | xz -d'):");
	trace_ext_puts(conf_str);
#endif
	return TEE_SUCCESS;
}
service_init(show_conf);
