/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

#ifdef LTC_MPI
#include <stdarg.h>

int ltc_init_multi(void **a, ...)
{
   void    **cur = a;
   int       np  = 0;
   va_list   args;

   va_start(args, a);
   while (cur != NULL) {
       if (mp_init(cur) != CRYPT_OK) {
          /* failed */
          va_list clean_list;

          va_start(clean_list, a);
          cur = a;
          while (np--) {
              mp_clear(*cur);
              cur = va_arg(clean_list, void**);
          }
          va_end(clean_list);
          va_end(args);
          return CRYPT_MEM;
       }
       ++np;
       cur = va_arg(args, void**);
   }
   va_end(args);
   return CRYPT_OK;
}

int ltc_init_multi_size(int size_bits, void **a, ...)
{
   void    **cur = a;
   int       np  = 0;
   va_list   args;

   va_start(args, a);
   while (cur != NULL) {
       if (mp_init_size(size_bits, cur) != CRYPT_OK) {
          /* failed */
          va_list clean_list;

          va_start(clean_list, a);
          cur = a;
          while (np--) {
              mp_clear(*cur);
              cur = va_arg(clean_list, void**);
          }
          va_end(clean_list);
          return CRYPT_MEM;
       }
       ++np;
       cur = va_arg(args, void**);
   }
   va_end(args);
   return CRYPT_OK;
}

void ltc_deinit_multi(void *a, ...)
{
   void     *cur = a;
   va_list   args;

   va_start(args, a);
   while (cur != NULL) {
       mp_clear(cur);
       cur = va_arg(args, void *);
   }
   va_end(args);
}

void ltc_cleanup_multi(void **a, ...)
{
   void **cur = a;
   va_list args;

   va_start(args, a);
   while (cur != NULL) {
      if (*cur != NULL) {
         mp_clear(*cur);
         *cur = NULL;
      }
      cur = va_arg(args, void**);
   }
   va_end(args);
}

#endif
