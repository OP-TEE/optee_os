/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/**
   @file ocb_shift_xor.c
   OCB implementation, internal function, by Tom St Denis
*/
#include "tomcrypt_private.h"

#ifdef LTC_OCB_MODE

/**
   Compute the shift/xor for OCB (internal function)
   @param ocb  The OCB state
   @param Z    The destination of the shift
*/
void ocb_shift_xor(ocb_state *ocb, unsigned char *Z)
{
   int x, y;
   y = ocb_ntz(ocb->block_index++);
   for (x = 0; x < ocb->block_len; x++) {
       ocb->Li[x] ^= ocb->Ls[y][x];
       Z[x]        = ocb->Li[x] ^ ocb->R[x];
   }
}

#endif
