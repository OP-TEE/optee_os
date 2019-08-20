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
  @file ec25519_import_pkcs8.c
  Generic import of a Curve/Ed25519 private key in PKCS#8 format, Steffen Jaeckel
*/

#ifdef LTC_CURVE25519

/**
  Generic import of a Curve/Ed25519 private key in PKCS#8 format
  @param in        The DER-encoded PKCS#8-formatted private key
  @param inlen     The length of the input data
  @param passwd    The password to decrypt the private key
  @param passwdlen Password's length (octets)
  @param key       [out] Where to import the key to
  @return CRYPT_OK if successful, on error all allocated memory is freed automatically
*/
int ec25519_import_pkcs8(const unsigned char *in, unsigned long inlen,
                       const void *pwd, unsigned long pwdlen,
                       enum ltc_oid_id id, sk_to_pk fp,
                       curve25519_key *key)
{
   int err;
   ltc_asn1_list *l = NULL;
   const char *oid;
   ltc_asn1_list alg_id[1];
   unsigned char private_key[34];
   unsigned long version, key_len;
   unsigned long tmpoid[16];

   LTC_ARGCHK(in  != NULL);
   LTC_ARGCHK(key != NULL);
   LTC_ARGCHK(fp != NULL);

   if ((err = pkcs8_decode_flexi(in, inlen, pwd, pwdlen, &l)) == CRYPT_OK) {

      LTC_SET_ASN1(alg_id, 0, LTC_ASN1_OBJECT_IDENTIFIER, tmpoid, sizeof(tmpoid) / sizeof(tmpoid[0]));

      key_len = sizeof(private_key);
      if ((err = der_decode_sequence_multi(l->data, l->size,
                                           LTC_ASN1_SHORT_INTEGER,      1uL, &version,
                                           LTC_ASN1_SEQUENCE,           1uL, alg_id,
                                           LTC_ASN1_OCTET_STRING,   key_len, private_key,
                                           LTC_ASN1_EOL,                0uL, NULL))
          != CRYPT_OK) {
         /* If there are attributes added after the private_key it is tagged with version 1 and
          * we get an 'input too long' error but the rest is already decoded and can be
          * handled the same as for version 0
          */
         if ((err == CRYPT_INPUT_TOO_LONG) && (version == 1)) {
            version = 0;
         } else {
            goto out;
         }
      }

      if ((err = pk_get_oid(id, &oid)) != CRYPT_OK) {
         goto out;
      }
      if ((err = pk_oid_cmp_with_asn1(oid, &alg_id[0])) != CRYPT_OK) {
         goto out;
      }

      if (version == 0) {
         key_len = sizeof(key->priv);
         if ((err = der_decode_octet_string(private_key, sizeof(private_key), key->priv, &key_len)) == CRYPT_OK) {
            fp(key->pub, key->priv);
            key->type = PK_PRIVATE;
            key->algo = id;
         }
      } else {
         err = CRYPT_PK_INVALID_TYPE;
      }
   }
out:
   if (l) der_free_sequence_flexi(l);
#ifdef LTC_CLEAN_STACK
   zeromem(private_key, sizeof(private_key));
#endif

   return err;
}

#endif

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
