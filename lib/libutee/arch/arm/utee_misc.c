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

/*
 * This version of get_rng_array() is used by the libmpa, when used on user side
 * This is why this function is not implemented in libutee for targets with
 * trusted os not split into kernel / user side. In such case, only the
 * get_rng_array() version from the kernel side is used.
 */
extern TEE_Result get_rng_array(void *buf, size_t blen);
TEE_Result get_rng_array(void *buf, size_t blen)
{
	return utee_cryp_random_number_generate(buf, blen);
}
