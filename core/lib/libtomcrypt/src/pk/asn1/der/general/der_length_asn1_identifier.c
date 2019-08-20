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
  @file der_length_asn1_identifier.c
  ASN.1 DER, determine the length when encoding the ASN.1 Identifier, Steffen Jaeckel
*/

#ifdef LTC_DER
/**
  Determine the length required when encoding the ASN.1 Identifier
  @param id    The ASN.1 identifier to encode
  @param idlen [out] The required length to encode list
  @return CRYPT_OK if successful
*/

int der_length_asn1_identifier(const ltc_asn1_list *id, unsigned long *idlen)
{
   return der_encode_asn1_identifier(id, NULL, idlen);
}

#endif

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
