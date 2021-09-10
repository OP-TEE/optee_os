// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2021, Linaro Limited
 * Copyright (c) 2021, Bootlin
 */

#include <kernel/dt_driver.h>
#include <sys/queue.h>

struct dt_driver_prov_list dt_driver_provider_list =
	SLIST_HEAD_INITIALIZER(dt_driver_provider_list);
