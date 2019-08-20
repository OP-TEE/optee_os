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

#ifdef LTC_DER

typedef struct {
   enum ltc_oid_id id;
   const char* oid;
} oid_table_entry;

static const oid_table_entry pka_oids[] = {
                                              { PKA_RSA,       "1.2.840.113549.1.1.1" },
                                              { PKA_DSA,       "1.2.840.10040.4.1" },
                                              { PKA_EC,        "1.2.840.10045.2.1" },
                                              { PKA_EC_PRIMEF, "1.2.840.10045.1.1" },
                                              { PKA_X25519,    "1.3.101.110" },
                                              { PKA_ED25519,   "1.3.101.112" },
};

/*
   Returns the OID requested.
   @return CRYPT_OK if valid
*/
int pk_get_oid(enum ltc_oid_id id, const char **st)
{
   unsigned int i;
   LTC_ARGCHK(st != NULL);
   for (i = 0; i < sizeof(pka_oids)/sizeof(pka_oids[0]); ++i) {
      if (pka_oids[i].id == id) {
         *st = pka_oids[i].oid;
         return CRYPT_OK;
      }
   }
   return CRYPT_INVALID_ARG;
}
#endif

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
