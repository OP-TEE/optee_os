/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file rsa_key.c
  Free an RSA key, Tom St Denis
  Basic operations on an RSA key, Steffen Jaeckel
*/

#ifdef LTC_MRSA
#include <stdarg.h>

static void s_mpi_shrink_multi(void **a, ...)
{
   void **cur;
   unsigned n;
   int err;
   va_list args;
   void *tmp[10] = { 0 };
   void **arg[10] = { 0 };

   /* We re-allocate in the order that we received the varargs */
   n = 0;
   err = CRYPT_ERROR;
   cur = a;
   va_start(args, a);
   while (cur != NULL) {
      if (n >= sizeof(tmp)/sizeof(tmp[0])) {
         goto out;
      }
      if (*cur != NULL) {
         arg[n] = cur;
         if ((err = mp_init_copy(&tmp[n], *arg[n])) != CRYPT_OK) {
            goto out;
         }
         n++;
      }
      cur = va_arg(args, void**);
   }
   va_end(args);

   /* but we clear the old values in the reverse order */
   while (n != 0 && arg[--n] != NULL) {
      mp_clear(*arg[n]);
      *arg[n] = tmp[n];
   }
out:
   va_end(args);
   /* clean-up after an error
    * or after this was called with too many args
    */
   if ((err != CRYPT_OK) ||
         (n >= sizeof(tmp)/sizeof(tmp[0]))) {
      for (n = 0; n < sizeof(tmp)/sizeof(tmp[0]); ++n) {
         if (tmp[n] != NULL) {
            mp_clear(tmp[n]);
         }
      }
   }
}

/**
  This shrinks the allocated memory of a RSA key

     It will use up some more memory temporarily,
     but then it will free-up the entire sequence that
     was once allocated when the key was created/populated.

     This only works with libtommath >= 1.2.0 in earlier versions
     it has the inverse effect due to the way it worked internally.
     Also works for GNU MP, tomsfastmath naturally shows no effect.

  @param key   The RSA key to shrink
*/
void rsa_shrink_key(rsa_key *key)
{
   LTC_ARGCHKVD(key != NULL);
   s_mpi_shrink_multi(&key->e, &key->d, &key->N, &key->dQ, &key->dP, &key->qP, &key->p, &key->q, NULL);
}

/**
  Init an RSA key
  @param key   The RSA key to free
  @return CRYPT_OK if successful
*/
int rsa_init(rsa_key *key)
{
   LTC_ARGCHK(key != NULL);
   return mp_init_multi(&key->e, &key->d, &key->N, &key->dQ, &key->dP, &key->qP, &key->p, &key->q, LTC_NULL);
}

/**
  Free an RSA key from memory
  @param key   The RSA key to free
*/
void rsa_free(rsa_key *key)
{
   LTC_ARGCHKVD(key != NULL);
   mp_cleanup_multi(&key->q, &key->p, &key->qP, &key->dP, &key->dQ, &key->N, &key->d, &key->e, LTC_NULL);
}

#endif
