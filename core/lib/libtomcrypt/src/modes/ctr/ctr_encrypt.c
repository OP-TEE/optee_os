// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2001-2007, Tom St Denis
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

/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 *
 * Tom St Denis, tomstdenis@gmail.com, http://libtom.org
 */
#include "tomcrypt.h"

/**
  @file ctr_encrypt.c
  CTR implementation, encrypt data, Tom St Denis
*/


#ifdef LTC_CTR_MODE

static void ctr_increment_counter(symmetric_CTR *ctr)
{
	int x;

	if (ctr->mode == CTR_COUNTER_LITTLE_ENDIAN) {
		for (x = 0; x < ctr->ctrlen; x++) {
			ctr->ctr[x] = (ctr->ctr[x] + 1) & 0xff;
			if (ctr->ctr[x])
				return;
		}
	} else {
		for (x = ctr->blocklen - 1; x >= ctr->ctrlen; x--) {
			ctr->ctr[x] = (ctr->ctr[x] + 1) & 0xff;
			if (ctr->ctr[x]) {
				return;
			}
		}
	}
}

/**
  CTR encrypt sub
  @param pt     Plaintext
  @param ct     [out] Ciphertext
  @param len    Length of plaintext (octets)
  @param ctr    CTR state
  @return CRYPT_OK if successful
*/
static int ctr_encrypt_sub(const unsigned char *pt, unsigned char *ct, unsigned long len, symmetric_CTR *ctr)
{
   int err;

   while (len) {
      /* is the pad empty? */
      if (ctr->padlen == ctr->blocklen) {
        /* encrypt counter into pad */
        if ((err = cipher_descriptor[ctr->cipher]->ecb_encrypt(ctr->ctr, ctr->pad, &ctr->key)) != CRYPT_OK) {
          return err;
        }
        ctr->padlen = 0;
      }
#ifdef LTC_FAST
      if (ctr->padlen == 0 && len >= (unsigned long)ctr->blocklen) {
         for (x = 0; x < ctr->blocklen; x += sizeof(LTC_FAST_TYPE)) {
            *((LTC_FAST_TYPE*)((unsigned char *)ct + x)) = *((LTC_FAST_TYPE*)((unsigned char *)pt + x)) ^
                                                           *((LTC_FAST_TYPE*)((unsigned char *)ctr->pad + x));
         }
       pt         += ctr->blocklen;
       ct         += ctr->blocklen;
       len        -= ctr->blocklen;
       ctr->padlen = ctr->blocklen;
       continue;
      }
#endif
      *ct++ = *pt++ ^ ctr->pad[ctr->padlen++];
      --len;

      /* done with one full block? if so, set counter for next block. */
      if (ctr->padlen == ctr->blocklen) {
         ctr_increment_counter(ctr);
      }
   }
   return CRYPT_OK;
}

/**
  CTR encrypt
  @param pt     Plaintext
  @param ct     [out] Ciphertext
  @param len    Length of plaintext (octets)
  @param ctr    CTR state
  @return CRYPT_OK if successful
*/
int ctr_encrypt(const unsigned char *pt, unsigned char *ct, unsigned long len, symmetric_CTR *ctr)
{
   unsigned long incr;
   int err;

   LTC_ARGCHK(pt != NULL);
   LTC_ARGCHK(ct != NULL);
   LTC_ARGCHK(ctr != NULL);

   if ((err = cipher_is_valid(ctr->cipher)) != CRYPT_OK) {
       return err;
   }

   /* is blocklen/padlen valid? */
   if (ctr->blocklen < 1 || ctr->blocklen > (int)sizeof(ctr->ctr) ||
       ctr->padlen   < 0 || ctr->padlen   > (int)sizeof(ctr->pad)) {
      return CRYPT_INVALID_ARG;
   }

#ifdef LTC_FAST
   if (ctr->blocklen % sizeof(LTC_FAST_TYPE)) {
      return CRYPT_INVALID_ARG;
   }
#endif

   if (cipher_descriptor[ctr->cipher]->accel_ctr_encrypt != NULL ) {
     /* handle acceleration only if not in the middle of a block, accelerator is present and length is >= a block size */
     if ((ctr->padlen == 0 || ctr->padlen == ctr->blocklen) && len >= (unsigned long)ctr->blocklen) {
       if ((err = cipher_descriptor[ctr->cipher]->accel_ctr_encrypt(pt, ct, len/ctr->blocklen, ctr->ctr, ctr->mode, &ctr->key)) != CRYPT_OK) {
         return err;
       }
       pt += (len / ctr->blocklen) * ctr->blocklen;
       ct += (len / ctr->blocklen) * ctr->blocklen;
       len %= ctr->blocklen;
       /* counter was changed by accelerator so mark pad empty (will need updating in ctr_encrypt_sub()) */
       ctr->padlen = ctr->blocklen;
     }

     /* try to re-synchronize on a block boundary for maximum use of acceleration */
     incr = ctr->blocklen - ctr->padlen;
     if (len >= incr + (unsigned long)ctr->blocklen) {
       if ((err = ctr_encrypt_sub(pt, ct, incr, ctr)) != CRYPT_OK) {
         return err;
       }
       pt += incr;
       ct += incr;
       len -= incr;
       return ctr_encrypt(pt, ct, len, ctr);
     }
   }

   return ctr_encrypt_sub(pt, ct, len, ctr);
}

#endif

/* $Source: /cvs/libtom/libtomcrypt/src/modes/ctr/ctr_encrypt.c,v $ */
/* $Revision: 1.22 $ */
/* $Date: 2007/02/22 20:26:05 $ */
