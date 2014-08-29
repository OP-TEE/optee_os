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

#include <stddef.h>
#include <string.h>
#include <kernel/tee_core_trace.h>
#include <kernel/tee_common_otp.h>

#define SHA256_HASH_SIZE 32
uint8_t hw_key_digest[SHA256_HASH_SIZE];

/*---------------------------------------------------------------------------*/
/*                             tee_otp_get_hw_unique_key                    */
/*---------------------------------------------------------------------------*/
/*
    This function reads out a hw unique key.

    \param[in]  hwkey data place holder for the key data read
    \param[out] None.
    \return None.

 */
/*---------------------------------------------------------------------------*/
void tee_otp_get_hw_unique_key(struct tee_hw_unique_key *hwkey)
{
	/* Copy the first part of the new hw key */
	memcpy(&hwkey->data[0], &hw_key_digest[0],
	       sizeof(struct tee_hw_unique_key));
}

int tee_otp_get_die_id(uint8_t *buffer, size_t len)
{
	size_t i;

	char pattern[4] = { 'B', 'E', 'E', 'F' };
	for (i = 0; i < len; i++)
		buffer[i] = pattern[i % 4];

	return 0;
}
