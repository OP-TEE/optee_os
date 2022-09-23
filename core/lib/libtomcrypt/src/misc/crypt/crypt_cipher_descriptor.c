/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file crypt_cipher_descriptor.c
  Stores the cipher descriptor table, Tom St Denis
*/

const struct ltc_cipher_descriptor *cipher_descriptor[TAB_SIZE];

LTC_MUTEX_GLOBAL(ltc_cipher_mutex)

