/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

#include "tomcrypt_private.h"

#ifdef LTC_SOBER128_STREAM

/**
   Encrypt (or decrypt) bytes of ciphertext (or plaintext) with SOBER128
   @param key     The key
   @param keylen  The key length
   @param iv      The initial vector
   @param ivlen   The initial vector length
   @param datain  The plaintext (or ciphertext)
   @param datalen The length of the input and output (octets)
   @param dataout [out] The ciphertext (or plaintext)
   @return CRYPT_OK if successful
*/
int sober128_stream_memory(const unsigned char *key,    unsigned long keylen,
                           const unsigned char *iv,     unsigned long ivlen,
                           const unsigned char *datain, unsigned long datalen,
                           unsigned char *dataout)
{
   sober128_state st;
   int err;

   if ((err = sober128_stream_setup(&st, key, keylen)) != CRYPT_OK) goto WIPE_KEY;
   if ((err = sober128_stream_setiv(&st, iv, ivlen))   != CRYPT_OK) goto WIPE_KEY;
   err = sober128_stream_crypt(&st, datain, datalen, dataout);
WIPE_KEY:
   sober128_stream_done(&st);
   return err;
}

#endif /* LTC_SOBER128_STREAM */
