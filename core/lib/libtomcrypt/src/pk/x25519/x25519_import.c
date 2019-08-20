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
  @file x25519_import.c
  Import a X25519 key from a binary packet, Steffen Jaeckel
*/

#ifdef LTC_CURVE25519

/**
  Import a X25519 key from a binary packet
  @param in     The packet to read
  @param inlen  The length of the input packet
  @param key    [out] Where to import the key to
  @return CRYPT_OK if successful, on error all allocated memory is freed automatically
*/
int x25519_import(const unsigned char *in, unsigned long inlen, curve25519_key *key)
{
   int err;
   unsigned long key_len;

   LTC_ARGCHK(in  != NULL);
   LTC_ARGCHK(key != NULL);

   /* There's only one case where the inlen is equal to the pubkey-size
    * and that's a raw pubkey, so let's just do a raw import.
    */
   if (inlen == sizeof(key->pub)) {
      XMEMCPY(key->pub, in, sizeof(key->pub));
      key->type = PK_PUBLIC;
      key->algo = PKA_X25519;
      return CRYPT_OK;
   }

   key_len = sizeof(key->pub);
   if ((err = x509_decode_subject_public_key_info(in, inlen, PKA_X25519, key->pub, &key_len, LTC_ASN1_EOL, NULL, 0uL)) == CRYPT_OK) {
      key->type = PK_PUBLIC;
      key->algo = PKA_X25519;
   }
   return err;
}

#endif

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
