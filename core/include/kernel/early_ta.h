/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2017, 2020, Linaro Limited
 * Copyright (c) 2020, Arm Limited.
 */
#ifndef __KERNEL_EARLY_TA_H
#define __KERNEL_EARLY_TA_H

#include <kernel/embedded_ts.h>
#include <scattered_array.h>
#include <stdint.h>
#include <tee_api_types.h>

#define for_each_early_ta(_ta) \
	SCATTERED_ARRAY_FOREACH(_ta, early_tas, struct embedded_ts)

#endif /* __KERNEL_EARLY_TA_H */

