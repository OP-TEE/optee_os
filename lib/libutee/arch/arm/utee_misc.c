// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#include <utee_misc.h>
#include "utee_syscalls.h"

/* utee_get_ta_exec_id - get a process/thread id for the current sequence */
unsigned int utee_get_ta_exec_id(void)
{
	/* no execution ID available */
	return 0;
}
