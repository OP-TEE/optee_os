/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

#ifdef LTC_DER

typedef struct {
   enum ltc_oid_id id;
   const char* oid;
} oid_table_entry;

static const oid_table_entry pka_oids[] = {
                                              { LTC_OID_RSA,       "1.2.840.113549.1.1.1" },
                                              { LTC_OID_DSA,       "1.2.840.10040.4.1" },
                                              { LTC_OID_EC,        "1.2.840.10045.2.1" },
                                              { LTC_OID_EC_PRIMEF, "1.2.840.10045.1.1" },
                                              { LTC_OID_X25519,    "1.3.101.110" },
                                              { LTC_OID_ED25519,   "1.3.101.112" },
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
