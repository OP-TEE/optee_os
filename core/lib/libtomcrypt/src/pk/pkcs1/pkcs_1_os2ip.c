/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file pkcs_1_os2ip.c
  Octet to Integer OS2IP, Tom St Denis
*/
#ifdef LTC_PKCS_1

/**
  Read a binary string into an mp_int
  @param n          [out] The mp_int destination
  @param in         The binary string to read
  @param inlen      The length of the binary string
  @return CRYPT_OK if successful
*/
int pkcs_1_os2ip(void *n, unsigned char *in, unsigned long inlen)
{
   return mp_read_unsigned_bin(n, in, inlen);
}

#endif /* LTC_PKCS_1 */

