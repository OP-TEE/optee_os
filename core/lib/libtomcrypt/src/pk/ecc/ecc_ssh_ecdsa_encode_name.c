/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
   @file ecc_ssh_ecdsa_encode_name.c
   Curve/OID to SSH+ECDSA name string mapping per RFC5656
   Russ Williams
*/

#ifdef LTC_SSH

/**
  Curve/OID to SSH+ECDSA name string mapping
  @param buffer    [out] The destination for the name
  @param buflen    [in/out] The max size and resulting size (including terminator) of the name
  @param key       A public or private ECC key
  @return CRYPT_OK if successful
*/
int ecc_ssh_ecdsa_encode_name(char *buffer, unsigned long *buflen, const ecc_key *key)
{
   char oidstr[64] = {0};
   unsigned long oidlen = sizeof(oidstr);
   int err, size = 0;

   LTC_ARGCHK(buffer != NULL);
   LTC_ARGCHK(buflen != NULL);
   LTC_ARGCHK(key != NULL);

   /* Get the OID of the curve */
   if ((err = ecc_get_oid_str(oidstr, &oidlen, key)) != CRYPT_OK) goto error;

   /* Check for three named curves: nistp256, nistp384, nistp521 */
   if (XSTRCMP("1.2.840.10045.3.1.7", oidstr) == 0) {
      /* nistp256 - secp256r1 - OID 1.2.840.10045.3.1.7 */
      size = snprintf(buffer, *buflen, "ecdsa-sha2-nistp256");
   }
   else if (XSTRCMP("1.3.132.0.34", oidstr) == 0) {
      /* nistp384 - secp384r1 - OID 1.3.132.0.34 */
      size = snprintf(buffer, *buflen, "ecdsa-sha2-nistp384");
   }
   else if (XSTRCMP("1.3.132.0.35", oidstr) == 0) {
      /* nistp521 - secp521r1 - OID 1.3.132.0.35 */
      size = snprintf(buffer, *buflen, "ecdsa-sha2-nistp521");
   } else {
      /* Otherwise we use the OID... */
      size = snprintf(buffer, *buflen, "ecdsa-sha2-%s", oidstr);
   }

   /* snprintf returns a negative value on error
    * or the size that would have been written, but limits to buflen-1 chars plus terminator */
   if (size < 0) {
      err = CRYPT_ERROR;
   } else if ((unsigned)size >= *buflen) {
      err = CRYPT_BUFFER_OVERFLOW;
   } else {
      err = CRYPT_OK;
   }
   *buflen = size + 1; /* the string length + NUL byte */

error:
   return err;
}

#endif
