/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/**
   @file ocb3_int_ntz.c
   OCB implementation, INTERNAL ONLY helper, by Tom St Denis
*/
#include "tomcrypt_private.h"

#ifdef LTC_OCB3_MODE

/**
   Returns the number of leading zero bits [from lsb up] (internal function)
   @param x  The 32-bit value to observe
   @return The number of bits [from the lsb up] that are zero
*/
int ocb3_int_ntz(unsigned long x)
{
   int c;
   x &= 0xFFFFFFFFUL;
   c = 0;
   while ((x & 1) == 0) {
      ++c;
      x >>= 1;
   }
   return c;
}

#endif
