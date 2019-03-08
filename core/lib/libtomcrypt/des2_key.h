/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014-2019, Linaro Limited
 */

static inline void get_des2_key(const uint8_t **key, size_t *key_len,
				uint8_t *tmp)
{
	if (*key_len == 16) {
		/*
		 * This corresponds to a 2DES key. The 2DES encryption
		 * algorithm is similar to 3DES. Both perform and
		 * encryption step, then a decryption step, followed
		 * by another encryption step (EDE). However 2DES uses
		 * the same key for both of the encryption (E) steps.
		 */
		memcpy(tmp, *key, 16);
		memcpy(tmp + 16, *key, 8);
		*key = tmp;
		*key_len = 24;
	}
}
