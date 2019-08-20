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

/**
  @file x25519_set_ku.c
  Set the parameters of a X25519 key, Steffen Jaeckel
*/

#ifdef LTC_CURVE25519

/**
   Set the parameters of a X25519 key

   In case k and u are given it is validated that u is really the
   corresponding public part of the key pair

   @param k        The k value (a.k.a scalar or private part)
   @param klen     The length of k
   @param u        The u-coordinate (a.k.a public part)
   @param ulen     The length of u
   @param key      [out] Destination of the key
   @return CRYPT_OK if successful
*/
int x25519_set_key(const unsigned char *k, unsigned long klen,
                   const unsigned char *u, unsigned long ulen,
                        curve25519_key *key)
{
   LTC_ARGCHK(key != NULL);

   if (k != NULL) {
      LTC_ARGCHK(klen == 32uL);
      XMEMCPY(key->priv, k, sizeof(key->priv));
      tweetnacl_crypto_scalarmult_base(key->pub, key->priv);
      if (u != NULL) {
         LTC_ARGCHK(ulen == 32uL);
         if (XMEM_NEQ(u, key->pub, sizeof(key->pub)) != 0) {
            zeromem(key, sizeof(*key));
            return CRYPT_INVALID_ARG;
         }
      }
      key->type = PK_PRIVATE;
   } else if (u != NULL) {
      LTC_ARGCHK(ulen == 32uL);
      XMEMCPY(key->pub, u, sizeof(key->pub));
      key->type = PK_PUBLIC;
   } else {
      return CRYPT_INVALID_ARG;
   }
   key->algo = PKA_X25519;

   return CRYPT_OK;
}

#endif

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
