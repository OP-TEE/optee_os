/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file crypt_prng_descriptor.c
  Stores the PRNG descriptors, Tom St Denis
*/
const struct ltc_prng_descriptor *prng_descriptor[TAB_SIZE];

LTC_MUTEX_GLOBAL(ltc_prng_mutex)

