/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file x509_decode_public_key_from_certificate.c
  ASN.1 DER/X.509, decode a certificate
*/

#ifdef LTC_DER

/* Check if it looks like a SubjectPublicKeyInfo */
#define LOOKS_LIKE_SPKI(l) ((l) != NULL)              \
&& ((l)->type == LTC_ASN1_SEQUENCE)                   \
&& ((l)->child != NULL)                               \
&& ((l)->child->type == LTC_ASN1_OBJECT_IDENTIFIER)   \
&& ((l)->next != NULL)                                \
&& ((l)->next->type == LTC_ASN1_BIT_STRING)

/**
  Try to decode the public key from a X.509 certificate
   @param in               The input buffer
   @param inlen            The length of the input buffer
   @param algorithm        One out of the enum #public_key_algorithms
   @param param_type       The parameters' type out of the enum ltc_asn1_type
   @param parameters       The parameters to include
   @param parameters_len   [in/out] The number of parameters to include
   @param callback         The callback
   @param ctx              The context passed to the callback
   @return CRYPT_OK on success, CRYPT_NOP if no SubjectPublicKeyInfo was found
*/
int x509_decode_public_key_from_certificate(const unsigned char *in, unsigned long inlen,
                                            enum ltc_oid_id algorithm, ltc_asn1_type param_type,
                                            ltc_asn1_list* parameters, unsigned long *parameters_len,
                                            public_key_decode_cb callback, void *ctx)
{
   int err;
   unsigned char *tmpbuf;
   unsigned long tmpbuf_len, tmp_inlen;
   ltc_asn1_list *decoded_list = NULL, *l;

   LTC_ARGCHK(in       != NULL);
   LTC_ARGCHK(inlen    != 0);
   LTC_ARGCHK(callback != NULL);

   tmpbuf_len = inlen;
   tmpbuf = XCALLOC(1, tmpbuf_len);
   if (tmpbuf == NULL) {
       err = CRYPT_MEM;
       goto LBL_OUT;
   }

   tmp_inlen = inlen;
   if ((err = der_decode_sequence_flexi(in, &tmp_inlen, &decoded_list)) == CRYPT_OK) {
      l = decoded_list;

      err = CRYPT_NOP;

      /* Move 2 levels up in the tree
         SEQUENCE
             SEQUENCE
                 ...
       */
      if ((l->type == LTC_ASN1_SEQUENCE) && (l->child != NULL)) {
         l = l->child;
         if ((l->type == LTC_ASN1_SEQUENCE) && (l->child != NULL)) {
            l = l->child;

            /* Move forward in the tree until we find this combination
                 ...
                 SEQUENCE
                     SEQUENCE
                         OBJECT IDENTIFIER <some PKA OID, e.g. 1.2.840.113549.1.1.1>
                         NULL
                     BIT STRING
             */
            do {
               /* The additional check for l->data is there to make sure
                * we won't try to decode a list that has been 'shrunk'
                */
               if ((l->type == LTC_ASN1_SEQUENCE)
                     && (l->data != NULL)
                     && LOOKS_LIKE_SPKI(l->child)) {
                  if (algorithm == LTC_OID_EC) {
                     err = callback(l->data, l->size, ctx);
                  } else {
                     err = x509_decode_subject_public_key_info(l->data, l->size,
                                                               algorithm, tmpbuf, &tmpbuf_len,
                                                               param_type, parameters, parameters_len);
                     if (err == CRYPT_OK) {
                        err = callback(tmpbuf, tmpbuf_len, ctx);
                        goto LBL_OUT;
                     }
                  }
               }
               l = l->next;
            } while(l);
         }
      }
   }

LBL_OUT:
   if (decoded_list) der_free_sequence_flexi(decoded_list);
   if (tmpbuf != NULL) XFREE(tmpbuf);

   return err;
}

#endif
