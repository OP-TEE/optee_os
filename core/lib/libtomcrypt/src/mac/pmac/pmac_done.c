/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file pmac_done.c
  PMAC implementation, terminate a session, by Tom St Denis
*/

#ifdef LTC_PMAC

int pmac_done(pmac_state *pmac, unsigned char *out, unsigned long *outlen)
{
   int err, x;

   LTC_ARGCHK(pmac != NULL);
   LTC_ARGCHK(out  != NULL);
   if ((err = cipher_is_valid(pmac->cipher_idx)) != CRYPT_OK) {
      return err;
   }

   if ((pmac->buflen > (int)sizeof(pmac->block)) || (pmac->buflen < 0) ||
       (pmac->block_len > (int)sizeof(pmac->block)) || (pmac->buflen > pmac->block_len)) {
      return CRYPT_INVALID_ARG;
   }


   /* handle padding.  If multiple xor in L/x */

   if (pmac->buflen == pmac->block_len) {
      /* xor Lr against the checksum */
      for (x = 0; x < pmac->block_len; x++) {
          pmac->checksum[x] ^= pmac->block[x] ^ pmac->Lr[x];
      }
   } else {
      /* otherwise xor message bytes then the 0x80 byte */
      for (x = 0; x < pmac->buflen; x++) {
          pmac->checksum[x] ^= pmac->block[x];
      }
      pmac->checksum[x] ^= 0x80;
   }

   /* encrypt it */
   if ((err = cipher_descriptor[pmac->cipher_idx].ecb_encrypt(pmac->checksum, pmac->checksum, &pmac->key)) != CRYPT_OK) {
      return err;
   }
   cipher_descriptor[pmac->cipher_idx].done(&pmac->key);

   /* store it */
   for (x = 0; x < pmac->block_len && x < (int)*outlen; x++) {
       out[x] = pmac->checksum[x];
   }
   *outlen = x;

#ifdef LTC_CLEAN_STACK
   zeromem(pmac, sizeof(*pmac));
#endif
   return CRYPT_OK;
}

#endif

