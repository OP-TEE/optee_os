/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
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

/* utee_malloc/realloc/free - call malloc lib support */
void *utee_malloc(size_t len)
{
	return malloc(len);
}

void *utee_realloc(void *buffer, size_t len)
{
	return realloc(buffer, len);
}

void *utee_calloc(size_t nb, size_t len)
{
	return calloc(len, nb);
}

void utee_free(void *buffer)
{
	free(buffer);
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
