/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

#include "tomcrypt_private.h"

#ifdef LTC_SALSA20

/**
   Encrypt (or decrypt) bytes of ciphertext (or plaintext) with Salsa20
   @param key     The key
   @param keylen  The key length
   @param iv      The initial vector
   @param ivlen   The initial vector length
   @param datain  The plaintext (or ciphertext)
   @param datalen The length of the input and output (octets)
   @param rounds  The number of rounds
   @param dataout [out] The ciphertext (or plaintext)
   @return CRYPT_OK if successful
*/
int salsa20_memory(const unsigned char *key,    unsigned long keylen,  unsigned long rounds,
                   const unsigned char *iv,     unsigned long ivlen,   ulong64 counter,
                   const unsigned char *datain, unsigned long datalen, unsigned char *dataout)
{
   salsa20_state st;
   int err;

   if ((err = salsa20_setup(&st, key, keylen, rounds))  != CRYPT_OK) goto WIPE_KEY;
   if ((err = salsa20_ivctr64(&st, iv, ivlen, counter)) != CRYPT_OK) goto WIPE_KEY;
   err = salsa20_crypt(&st, datain, datalen, dataout);
WIPE_KEY:
   salsa20_done(&st);
   return err;
}

#endif /* LTC_SALSA20 */
