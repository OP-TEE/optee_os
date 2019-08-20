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
  @file ed25519_make_key.c
  Create an Ed25519 key, Steffen Jaeckel
*/

#ifdef LTC_CURVE25519

/**
   Create an Ed25519 key
   @param prng     An active PRNG state
   @param wprng    The index of the PRNG desired
   @param key      [out] Destination of a newly created private key pair
   @return CRYPT_OK if successful
*/
int ed25519_make_key(prng_state *prng, int wprng, curve25519_key *key)
{
   int err;

   LTC_ARGCHK(prng != NULL);
   LTC_ARGCHK(key  != NULL);

   if ((err = tweetnacl_crypto_sign_keypair(prng, wprng, key->pub, key->priv)) != CRYPT_OK) {
      return err;
   }

   key->type = PK_PRIVATE;
   key->algo = PKA_ED25519;

   return err;
}

#endif

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
