/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
   @file burn_stack.c
   Burn stack, Tom St Denis
*/

/**
   Burn some stack memory
   @param len amount of stack to burn in bytes
*/
void burn_stack(unsigned long len)
{
   unsigned char buf[32];
   zeromem(buf, sizeof(buf));
   if (len > (unsigned long)sizeof(buf)) {
      burn_stack(len - sizeof(buf));
   }
}


