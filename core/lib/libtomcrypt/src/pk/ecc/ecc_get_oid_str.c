/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

#include "tomcrypt_private.h"

#ifdef LTC_MECC

/** Extract OID as a string from ECC key
  @param out    [out] destination buffer
  @param outlen [in/out] Length of destination buffer and final output size (without terminating NUL byte)
  @param key    The ECC key
  Return        CRYPT_OK on success
*/

int ecc_get_oid_str(char *out, unsigned long *outlen, const ecc_key *key)
{
   LTC_ARGCHK(key != NULL);

   return pk_oid_num_to_str(key->dp.oid, key->dp.oidlen, out, outlen);
}

#endif
