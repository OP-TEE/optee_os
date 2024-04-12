/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
   @file lrw_done.c
   LRW_MODE implementation, Free resources, Tom St Denis
*/

#ifdef LTC_LRW_MODE

/**
  Terminate a LRW state
  @param lrw   The state to terminate
  @return CRYPT_OK if successful
*/
int lrw_done(symmetric_LRW *lrw)
{
   int err;

   LTC_ARGCHK(lrw != NULL);

   if ((err = cipher_is_valid(lrw->cipher)) != CRYPT_OK) {
      return err;
   }
   cipher_descriptor[lrw->cipher].done(&lrw->key);

   return CRYPT_OK;
}

#endif
