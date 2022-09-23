/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
   @file dsa_free.c
   DSA implementation, free a DSA key, Tom St Denis
*/

#ifdef LTC_MDSA

/**
   Free a DSA key
   @param key   The key to free from memory
*/
void dsa_free(dsa_key *key)
{
   LTC_ARGCHKVD(key != NULL);
   mp_cleanup_multi(&key->y, &key->x, &key->q, &key->g, &key->p, LTC_NULL);
   key->type = key->qord = 0;
}

#endif
