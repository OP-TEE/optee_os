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

/* Implements ECC over Z/pZ for curve y^2 = x^3 - 3x + b
 *
 * All curves taken from NIST recommendation paper of July 1999
 * Available at http://csrc.nist.gov/cryptval/dss.htm
 */
#include "tomcrypt.h"

/**
  @file ecc_ansi_x963_export.c
  ECC Crypto, Tom St Denis
*/  

#ifdef LTC_MECC

/** ECC X9.63 (Sec. 4.3.6) uncompressed export
  @param key     Key to export
  @param out     [out] destination of export
  @param outlen  [in/out]  Length of destination and final output size
  Return CRYPT_OK on success
*/
int ecc_ansi_x963_export(ecc_key *key, unsigned char *out, unsigned long *outlen)
{
   unsigned char buf[ECC_BUF_SIZE];
   unsigned long numlen, xlen, ylen;

   LTC_ARGCHK(key    != NULL);
   LTC_ARGCHK(outlen != NULL);

   if (ltc_ecc_is_valid_idx(key->idx) == 0) {
      return CRYPT_INVALID_ARG;
   }
   numlen = key->dp->size;
   xlen = mp_unsigned_bin_size(key->pubkey.x);
   ylen = mp_unsigned_bin_size(key->pubkey.y);

   if (xlen > numlen || ylen > numlen || sizeof(buf) < numlen) {
      return CRYPT_BUFFER_OVERFLOW;
   }

   if (*outlen < (1 + 2*numlen)) {
      *outlen = 1 + 2*numlen;
      return CRYPT_BUFFER_OVERFLOW;
   }

   LTC_ARGCHK(out    != NULL);

   /* store byte 0x04 */
   out[0] = 0x04;

   /* pad and store x */
   zeromem(buf, sizeof(buf));
   mp_to_unsigned_bin(key->pubkey.x, buf + (numlen - xlen));
   XMEMCPY(out+1, buf, numlen);

   /* pad and store y */
   zeromem(buf, sizeof(buf));
   mp_to_unsigned_bin(key->pubkey.y, buf + (numlen - ylen));
   XMEMCPY(out+1+numlen, buf, numlen);

   *outlen = 1 + 2*numlen;
   return CRYPT_OK;
}

#endif

/* $Source: /cvs/libtom/libtomcrypt/src/pk/ecc/ecc_ansi_x963_export.c,v $ */
/* $Revision: 1.6 $ */
/* $Date: 2007/05/12 14:32:35 $ */
