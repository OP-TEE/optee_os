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
  @file error_to_string.c
  Convert error codes to ASCII strings, Tom St Denis
*/

static const char * const err_2_str[] =
{
   "CRYPT_OK",
   "CRYPT_ERROR",
   "Non-fatal 'no-operation' requested.",

   "Invalid key size.",
   "Invalid number of rounds for block cipher.",
   "Algorithm failed test vectors.",

   "Buffer overflow.",
   "Invalid input packet.",

   "Invalid number of bits for a PRNG.",
   "Error reading the PRNG.",

   "Invalid cipher specified.",
   "Invalid hash specified.",
   "Invalid PRNG specified.",

   "Out of memory.",

   "Invalid PK key or key type specified for function.",
   "A private PK key is required.",

   "Invalid argument provided.",
   "File Not Found",

   "Invalid PK type.",

   "An overflow of a value was detected/prevented.",

   "An ASN.1 decoding error occurred.",

   "The input was longer than expected.",

   "Invalid sized parameter.",

   "Invalid size for prime.",

   "Invalid padding.",

   "Hash applied to too many bits.",
};

/**
   Convert an LTC error code to ASCII
   @param err    The error code
   @return A pointer to the ASCII NUL terminated string for the error or "Invalid error code." if the err code was not valid.
*/
const char *error_to_string(int err)
{
   if (err < 0 || err >= (int)(sizeof(err_2_str)/sizeof(err_2_str[0]))) {
      return "Invalid error code.";
   }
   return err_2_str[err];
}


/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
