/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
   @file f8_done.c
   F8 implementation, finish chain, Tom St Denis
*/

#ifdef LTC_F8_MODE

/** Terminate the chain
  @param f8    The F8 chain to terminate
  @return CRYPT_OK on success
*/
int f8_done(symmetric_F8 *f8)
{
   int err;
   LTC_ARGCHK(f8 != NULL);

   if ((err = cipher_is_valid(f8->cipher)) != CRYPT_OK) {
      return err;
   }
   cipher_descriptor[f8->cipher].done(&f8->key);
   return CRYPT_OK;
}



#endif
