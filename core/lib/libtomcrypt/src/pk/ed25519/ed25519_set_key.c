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
  @file ed25519_set_ku.c
  Set the parameters of an Ed25519 key, Steffen Jaeckel
*/

#ifdef LTC_CURVE25519

/**
   Set the parameters of an Ed25519 key

   In case sk and pk are given it is validated that pk is really the
   corresponding public part of the key pair.

   @param sk       The secret key
   @param sklen    The length of sk
   @param pk       The public key
   @param pklen    The length of pk
   @param key      [out] Destination of the key
   @return CRYPT_OK if successful
*/
int ed25519_set_key(const unsigned char *sk, unsigned long sklen,
                    const unsigned char *pk, unsigned long pklen,
                         curve25519_key *key)
{
   LTC_ARGCHK(key != NULL);

   if (sk != NULL) {
      LTC_ARGCHK(sklen == 32uL);
      XMEMCPY(key->priv, sk, sizeof(key->priv));
      tweetnacl_crypto_sk_to_pk(key->pub, key->priv);
      if (pk != NULL) {
         LTC_ARGCHK(pklen == 32uL);
         if (XMEM_NEQ(pk, key->pub, sizeof(key->pub)) != 0) {
            zeromem(key, sizeof(*key));
            return CRYPT_INVALID_ARG;
         }
      }
      key->type = PK_PRIVATE;
   } else if (pk != NULL) {
      LTC_ARGCHK(pklen == 32uL);
      XMEMCPY(key->pub, pk, sizeof(key->pub));
      key->type = PK_PUBLIC;
   } else {
      return CRYPT_INVALID_ARG;
   }
   key->algo = PKA_ED25519;

   return CRYPT_OK;
}

#endif

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
