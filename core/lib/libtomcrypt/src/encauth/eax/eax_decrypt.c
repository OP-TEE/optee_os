/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/**
    @file eax_decrypt.c
    EAX implementation, decrypt block, by Tom St Denis
*/
#include "tomcrypt_private.h"

#ifdef LTC_EAX_MODE

/**
   Decrypt data with the EAX protocol
   @param eax     The EAX state
   @param ct      The ciphertext
   @param pt      [out] The plaintext
   @param length  The length (octets) of the ciphertext
   @return CRYPT_OK if successful
*/
int eax_decrypt(eax_state *eax, const unsigned char *ct, unsigned char *pt,
                unsigned long length)
{
   int err;

   LTC_ARGCHK(eax != NULL);
   LTC_ARGCHK(pt  != NULL);
   LTC_ARGCHK(ct  != NULL);

   /* omac ciphertext */
   if ((err = omac_process(&eax->ctomac, ct, length)) != CRYPT_OK) {
      return err;
   }

   /* decrypt  */
   return ctr_decrypt(ct, pt, length, &eax->ctr);
}

#endif
