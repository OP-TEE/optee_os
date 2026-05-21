/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef _RTABLE_H_
#define _RTABLE_H_

#include <resource_table.h>

TEE_Result pas_get_resource_table(uint32_t pas_id, struct resource_table *rt,
				  size_t *rt_size);

#endif /* _RTABLE_H_ */
