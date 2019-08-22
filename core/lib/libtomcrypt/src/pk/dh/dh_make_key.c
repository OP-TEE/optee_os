// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2001-2007, Tom St Denis
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

#include "tomcrypt_private.h"
#include <stdint.h>

/*
 * Make a DH key [private key pair]
 * @param prng     An active PRNG state
 * @param wprng    The index for the PRNG you desire to use
 * @param keysize  The key size (octets) desired of the private key
 * @param q        If not null, then the private key is in the range
 *                 [2, q-2] where q is called the subprime
 * @param xbits    If not 0, then the private key has 'xbits' bits
 * @note           The private key must always be less than p-1
 * @param key      [in/out] Where the newly created DH key will be stored
 *                  g and p are provided as input in the key
 *                  type, x and y are output of this function
 * @return CRYPT_OK if successful, note: on error all allocated memory will be
 *         freed automatically.
*/

int dh_make_key(prng_state *prng, int wprng, void *q, int xbits, dh_key *key)
{
	int err = 0;
	int key_size = 0;	/* max key size, in bytes */
	int key_size_p = 0;	/* key size of p */
	int key_size_q = 0;	/* key size of p */
	void *arg_mod = 0;
	uint8_t *buf = 0;	/* intermediate buffer to have a raw random  */

	/*
	 * Check the arguments
	 */
	LTC_ARGCHK(key != NULL);
	LTC_ARGCHK(key->base != NULL);
	LTC_ARGCHK(key->prime != NULL);
	err = prng_is_valid(wprng);
	if (err != CRYPT_OK)
		return err;

	/*
	 * Set the key size and check constraints
	 */
	if (xbits) {
		LTC_ARGCHK((xbits % 8) == 0);
		key_size = xbits / 8;
	}
	key_size_p = mp_unsigned_bin_size(key->prime);
	if (q)
		key_size_q = mp_unsigned_bin_size(q);
	if (key_size) {
		/* check the constraints */
		LTC_ARGCHK(key_size <= key_size_p);
		LTC_ARGCHK((q == NULL) || (key_size <= key_size_q));
	} else {
		if (q)
			key_size = MIN(key_size_p, key_size_q);
		else
			key_size =key_size_p;
	}

	/* Set the argument we will make the modulo against to */
	if ((q != NULL) && (key_size_q < key_size_p))
		arg_mod = q;
	else
		arg_mod = key->prime;

	/* initialize the key */
	key->x = NULL;
	key->y = NULL;
	err = mp_init_multi(&key->x, &key->y, NULL);
	if (err != CRYPT_OK)
		goto error;

	/* Initialize the buffer used to store the random number */
	buf = XMALLOC(key_size);
	if (buf == NULL) {
		err = CRYPT_MEM;
		goto error;
	}

	/* generate the private key in a raw-buffer */
	if (prng_descriptor[wprng]->read(buf, key_size, prng) !=
	    (unsigned long)key_size) {
		err = CRYPT_ERROR_READPRNG;
		goto error;
	}

	/*
	 * Transform it as a Big Number compatible with p and q
	 */
	err = mp_read_unsigned_bin(key->y, buf, key_size);
	if (err != CRYPT_OK)
		goto error;
	err = mp_mod(key->y, arg_mod, key->x);
	if (err != CRYPT_OK)
		goto error;

	/* generate the public key key->y */
	err = mp_exptmod(key->base, key->x, key->prime, key->y);
	if (err != CRYPT_OK)
		goto error;

	/* no error */
	err = CRYPT_OK;

error:
	if (err != CRYPT_OK)
		mp_clear_multi(key->x, key->y, NULL);
	if (buf)
		XFREE(buf);

	return err;
}
