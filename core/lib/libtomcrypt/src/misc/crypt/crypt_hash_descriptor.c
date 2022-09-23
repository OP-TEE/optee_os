/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file crypt_hash_descriptor.c
  Stores the hash descriptor table, Tom St Denis
*/

const struct ltc_hash_descriptor *hash_descriptor[TAB_SIZE];

LTC_MUTEX_GLOBAL(ltc_hash_mutex)

