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
  @file rsa_import.c
  Import an RSA key from a X.509 certificate, Steffen Jaeckel
*/

#ifdef LTC_MRSA

static int _rsa_decode(const unsigned char *in, unsigned long inlen, rsa_key *key)
{
   /* now it should be SEQUENCE { INTEGER, INTEGER } */
   return der_decode_sequence_multi(in, inlen,
                                        LTC_ASN1_INTEGER, 1UL, key->N,
                                        LTC_ASN1_INTEGER, 1UL, key->e,
                                        LTC_ASN1_EOL,     0UL, NULL);
}

/**
  Import an RSA key from a X.509 certificate
  @param in      The packet to import from
  @param inlen   It's length (octets)
  @param key     [out] Destination for newly imported key
  @return CRYPT_OK if successful, upon error allocated memory is freed
*/
int rsa_import_x509(const unsigned char *in, unsigned long inlen, rsa_key *key)
{
   int           err;

   LTC_ARGCHK(in          != NULL);
   LTC_ARGCHK(key         != NULL);
   LTC_ARGCHK(ltc_mp.name != NULL);

   /* init key */
   if ((err = mp_init_multi(&key->e, &key->d, &key->N, &key->dQ,
                            &key->dP, &key->qP, &key->p, &key->q, NULL)) != CRYPT_OK) {
      return err;
   }

   if ((err = x509_decode_public_key_from_certificate(in, inlen,
                                                      PKA_RSA, LTC_ASN1_NULL,
                                                      NULL, NULL,
                                                      (public_key_decode_cb)_rsa_decode, key)) != CRYPT_OK) {
      rsa_free(key);
   } else {
      key->type = PK_PUBLIC;
   }

   return err;
}

#endif /* LTC_MRSA */


/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
