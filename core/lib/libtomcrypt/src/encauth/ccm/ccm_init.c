// SPDX-License-Identifier: BSD-2-Clause
/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */
#include "tomcrypt_private.h"

#ifdef LTC_CCM_MODE

/**
  Initialize a CCM state
  @param ccm     The CCM state to initialize
  @param cipher  The index of the cipher to use
  @param key     The secret key
  @param keylen  The length of the secret key
  @param ptlen   The length of the plain/cipher text that will be processed
  @param taglen  The max length of the MAC tag
  @param aadlen  The length of the AAD

  @return CRYPT_OK on success
 */
int ccm_init(ccm_state *ccm, int cipher,
             const unsigned char *key, int keylen, int ptlen, int taglen, int aadlen)
{
   int            err;

   LTC_ARGCHK(ccm    != NULL);
   LTC_ARGCHK(key    != NULL);

   XMEMSET(ccm, 0, sizeof(ccm_state));

   /* check cipher input */
   if ((err = cipher_is_valid(cipher)) != CRYPT_OK) {
      return err;
   }
   if (cipher_descriptor[cipher]->block_length != 16) {
      return CRYPT_INVALID_CIPHER;
   }

   /* make sure the taglen is valid */
   if (taglen < 4 || taglen > 16 || (taglen % 2) == 1) {
      return CRYPT_INVALID_ARG;
   }
   ccm->taglen = taglen;

   /* schedule key */
   if ((err = cipher_descriptor[cipher]->setup(key, keylen, 0, &ccm->K)) != CRYPT_OK) {
      return err;
   }
   ccm->cipher = cipher;

   /* let's get the L value */
   ccm->ptlen = ptlen;
   ccm->L   = 0;
   while (ptlen) {
      ++ccm->L;
      ptlen >>= 8;
   }
   if (ccm->L <= 1) {
      ccm->L = 2;
   }

   ccm->aadlen = aadlen;
   return CRYPT_OK;
}

#endif

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
