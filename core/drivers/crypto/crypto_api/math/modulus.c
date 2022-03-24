// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2018-2020 NXP
 *
 * Brief   Cryptographic library using the NXP CAAM driver.
 *         Mathematical Modulus operation implementation.
 */
#include <drvcrypt.h>
#include <drvcrypt_math.h>
#include <string.h>
#include <util.h>

TEE_Result drvcrypt_xor_mod_n(struct drvcrypt_mod_op *data)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	struct drvcrypt_math *math = NULL;

	if (!data->a.data || !data->a.length || !data->b.data ||
	    !data->b.length || !data->result.data || !data->result.length ||
	    !data->n.length)
		return TEE_ERROR_BAD_PARAMETERS;

	if (data->result.length < data->n.length)
		return TEE_ERROR_BAD_PARAMETERS;

	math = drvcrypt_get_ops(CRYPTO_MATH);
	if (math) {
		/* Operation done by Math driver */
		ret = math->xor_mod_n(data);
	} else {
		/* Operation done by Software */
		size_t min = 0, idx = 0;

		/* Calculate the minimum size to do A xor B */
		min = MIN(data->a.length, data->b.length);
		min = MIN(min, data->n.length);

		for (; idx < min; idx++)
			data->result.data[idx] =
				data->a.data[idx] ^ data->b.data[idx];

		if (min < data->n.length) {
			/* Complete result to make a N modulus number */
			if (data->a.length > min) {
				memcpy(&data->result.data[idx],
				       &data->a.data[idx],
				       data->n.length - min);
			} else if (data->b.length > min) {
				memcpy(&data->result.data[idx],
				       &data->b.data[idx],
				       data->n.length - min);
			} else {
				memset(&data->result.data[idx], 0,
				       data->n.length - min);
			}
		}

		ret = TEE_SUCCESS;
	}

	return ret;
}
