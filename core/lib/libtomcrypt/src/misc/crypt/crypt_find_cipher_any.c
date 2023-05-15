/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file crypt_find_cipher_any.c
  Find a cipher in the descriptor tables, Tom St Denis
*/

/**
   Find a cipher flexibly.  First by name then if not present by block and key size
   @param name        The name of the cipher desired
   @param blocklen    The minimum length of the block cipher desired (octets)
   @param keylen      The minimum length of the key size desired (octets)
   @return >= 0 if found, -1 if not present
*/
int find_cipher_any(const char *name, int blocklen, int keylen)
{
   int x;

   if(name != NULL) {
      x = find_cipher(name);
      if (x != -1) return x;
   }

   LTC_MUTEX_LOCK(&ltc_cipher_mutex);
   for (x = 0; x < TAB_SIZE; x++) {
       if (cipher_descriptor[x] == NULL) {
          continue;
       }
       if (blocklen <= (int)cipher_descriptor[x]->block_length && keylen <= (int)cipher_descriptor[x]->max_key_length) {
          LTC_MUTEX_UNLOCK(&ltc_cipher_mutex);
          return x;
       }
   }
   LTC_MUTEX_UNLOCK(&ltc_cipher_mutex);
   return -1;
}
