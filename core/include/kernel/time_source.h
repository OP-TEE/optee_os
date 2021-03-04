/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, Linaro Limited
 */

#include <kernel/tee_time.h>

struct time_source {
	const char *name;
	uint32_t protection_level;
	TEE_Result (*get_sys_time)(TEE_Time *time);
};
void time_source_init(void);

#define REGISTER_TIME_SOURCE(source)	\
	void time_source_init(void) { \
		_time_source = source; \
	}

extern struct time_source _time_source;
