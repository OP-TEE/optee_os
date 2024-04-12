/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

#include "tomcrypt_private.h"

#ifdef LTC_MDH

/**
  Binary export a DH key to a buffer
  @param out    [out] The destination for the key
  @param outlen [in/out] The max size and resulting size of the DH key
  @param type   Which type of key (PK_PRIVATE or PK_PUBLIC)
  @param key    The key you wish to export
  @return CRYPT_OK if successful
*/
int dh_export_key(void *out, unsigned long *outlen, int type, const dh_key *key)
{
   unsigned long len;
   void *k;

   LTC_ARGCHK(out    != NULL);
   LTC_ARGCHK(outlen != NULL);
   LTC_ARGCHK(key    != NULL);

   k = (type == PK_PRIVATE) ? key->x : key->y;
   len = mp_unsigned_bin_size(k);

   if (*outlen < len) {
      *outlen = len;
      return CRYPT_BUFFER_OVERFLOW;
   }
   *outlen = len;

   return mp_to_unsigned_bin(k, out);
}

#endif /* LTC_MDH */
