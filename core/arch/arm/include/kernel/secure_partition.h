/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2020, Arm Limited.
 */
#ifndef KERNEL_SECURE_PARTITION_H
#define KERNEL_SECURE_PARTITION_H

#include <kernel/embedded_ts.h>
#include <stdint.h>
#include <tee_api_types.h>

#define for_each_secure_partition(_sp) \
	SCATTERED_ARRAY_FOREACH(_sp, sp_images, struct embedded_ts)

#endif /* KERNEL_SECURE_PARTITION_H */

