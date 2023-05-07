/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/**
   @file ocb_done_encrypt.c
   OCB implementation, terminate encryption, by Tom St Denis
*/
#include "tomcrypt_private.h"

#ifdef LTC_OCB_MODE

/**
   Terminate an encryption OCB state
   @param ocb       The OCB state
   @param pt        Remaining plaintext (if any)
   @param ptlen     The length of the plaintext (octets)
   @param ct        [out] The ciphertext (if any)
   @param tag       [out] The tag for the OCB stream
   @param taglen    [in/out] The max size and resulting size of the tag
   @return CRYPT_OK if successful
*/
int ocb_done_encrypt(ocb_state *ocb, const unsigned char *pt, unsigned long ptlen,
                     unsigned char *ct, unsigned char *tag, unsigned long *taglen)
{
   LTC_ARGCHK(ocb    != NULL);
   LTC_ARGCHK(pt     != NULL);
   LTC_ARGCHK(ct     != NULL);
   LTC_ARGCHK(tag    != NULL);
   LTC_ARGCHK(taglen != NULL);
   return s_ocb_done(ocb, pt, ptlen, ct, tag, taglen, 0);
}

#endif

