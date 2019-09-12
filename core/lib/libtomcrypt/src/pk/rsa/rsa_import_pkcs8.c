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
  @file rsa_import_pkcs8.c
  Import a PKCS RSA key
*/

#ifdef LTC_MRSA

/* Public-Key Cryptography Standards (PKCS) #8:
 * Private-Key Information Syntax Specification Version 1.2
 * https://tools.ietf.org/html/rfc5208
 *
 * PrivateKeyInfo ::= SEQUENCE {
 *      version                   Version,
 *      privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
 *      privateKey                PrivateKey,
 *      attributes           [0]  IMPLICIT Attributes OPTIONAL }
 * where:
 * - Version ::= INTEGER
 * - PrivateKeyAlgorithmIdentifier ::= AlgorithmIdentifier
 * - PrivateKey ::= OCTET STRING
 * - Attributes ::= SET OF Attribute
 *
 * EncryptedPrivateKeyInfo ::= SEQUENCE {
 *        encryptionAlgorithm  EncryptionAlgorithmIdentifier,
 *        encryptedData        EncryptedData }
 * where:
 * - EncryptionAlgorithmIdentifier ::= AlgorithmIdentifier
 * - EncryptedData ::= OCTET STRING
 */

/**
  Import an RSAPrivateKey in PKCS#8 format
  @param in        The packet to import from
  @param inlen     It's length (octets)
  @param passwd    The password for decrypting privkey
  @param passwdlen Password's length (octets)
  @param key       [out] Destination for newly imported key
  @return CRYPT_OK if successful, upon error allocated memory is freed
*/
int rsa_import_pkcs8(const unsigned char *in, unsigned long inlen,
                     const void *passwd, unsigned long passwdlen,
                     rsa_key *key)
{
   int           err;
   void          *zero, *iter;
   unsigned char *buf1 = NULL, *buf2 = NULL;
   unsigned long buf1len, buf2len;
   unsigned long oid[16];
   const char    *rsaoid;
   ltc_asn1_list alg_seq[2], top_seq[3];
   ltc_asn1_list *l = NULL;
   unsigned char *decrypted = NULL;
   unsigned long decryptedlen;

   LTC_ARGCHK(in          != NULL);
   LTC_ARGCHK(key         != NULL);
   LTC_ARGCHK(ltc_mp.name != NULL);

   /* get RSA alg oid */
   err = pk_get_oid(PKA_RSA, &rsaoid);
   if (err != CRYPT_OK) { goto LBL_NOFREE; }

   /* alloc buffers */
   buf1len = inlen; /* approx. */
   buf1 = XMALLOC(buf1len);
   if (buf1 == NULL) { err = CRYPT_MEM; goto LBL_NOFREE; }
   buf2len = inlen; /* approx. */
   buf2 = XMALLOC(buf2len);
   if (buf2 == NULL) { err = CRYPT_MEM; goto LBL_FREE1; }

   /* init key */
   err = mp_init_multi(&key->e, &key->d, &key->N, &key->dQ, &key->dP, &key->qP, &key->p, &key->q, &zero, &iter, NULL);
   if (err != CRYPT_OK) { goto LBL_FREE2; }

   /* try to decode encrypted priv key */
   if ((err = pkcs8_decode_flexi(in, inlen, passwd, passwdlen, &l)) != CRYPT_OK) {
      goto LBL_ERR;
   }
   decrypted    = l->data;
   decryptedlen = l->size;

   /* try to decode unencrypted priv key */
   LTC_SET_ASN1(alg_seq, 0, LTC_ASN1_OBJECT_IDENTIFIER, oid, 16UL);
   LTC_SET_ASN1(alg_seq, 1, LTC_ASN1_NULL, NULL, 0UL);
   LTC_SET_ASN1(top_seq, 0, LTC_ASN1_INTEGER, zero, 1UL);
   LTC_SET_ASN1(top_seq, 1, LTC_ASN1_SEQUENCE, alg_seq, 2UL);
   LTC_SET_ASN1(top_seq, 2, LTC_ASN1_OCTET_STRING, buf1, buf1len);
   err=der_decode_sequence(decrypted, decryptedlen, top_seq, 3UL);
   if (err != CRYPT_OK) { goto LBL_ERR; }

   /* check alg oid */
   if ((err = pk_oid_cmp_with_asn1(rsaoid, &alg_seq[0])) != CRYPT_OK) {
      goto LBL_ERR;
   }

   err = der_decode_sequence_multi(buf1, top_seq[2].size,
                                   LTC_ASN1_INTEGER, 1UL, zero,
                                   LTC_ASN1_INTEGER, 1UL, key->N,
                                   LTC_ASN1_INTEGER, 1UL, key->e,
                                   LTC_ASN1_INTEGER, 1UL, key->d,
                                   LTC_ASN1_INTEGER, 1UL, key->p,
                                   LTC_ASN1_INTEGER, 1UL, key->q,
                                   LTC_ASN1_INTEGER, 1UL, key->dP,
                                   LTC_ASN1_INTEGER, 1UL, key->dQ,
                                   LTC_ASN1_INTEGER, 1UL, key->qP,
                                   LTC_ASN1_EOL,     0UL, NULL);
   if (err != CRYPT_OK) { goto LBL_ERR; }
   key->type = PK_PRIVATE;
   err = CRYPT_OK;
   goto LBL_FREE2;

LBL_ERR:
   rsa_free(key);
LBL_FREE2:
   if (l) der_free_sequence_flexi(l);
   mp_clear_multi(iter, zero, NULL);
   XFREE(buf2);
LBL_FREE1:
   XFREE(buf1);
LBL_NOFREE:
   return err;
}

#endif /* LTC_MRSA */

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
