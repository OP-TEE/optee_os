/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

#include "tomcrypt_private.h"

#ifdef LTC_PKCS_12

int pkcs12_kdf(               int   hash_id,
               const unsigned char *pw,         unsigned long pwlen,
               const unsigned char *salt,       unsigned long saltlen,
                     unsigned int   iterations, unsigned char purpose,
                     unsigned char *out,        unsigned long outlen)
{
   unsigned long u = hash_descriptor[hash_id]->hashsize;
   unsigned long v = hash_descriptor[hash_id]->blocksize;
   unsigned long c = (outlen + u - 1) / u;
   unsigned long Slen = ((saltlen + v - 1) / v) * v;
   unsigned long Plen = ((pwlen + v - 1) / v) * v;
   unsigned long k = (Plen + Slen) / v;
   unsigned long Alen, keylen = 0;
   unsigned int tmp, i, j, n;
   unsigned char ch;
   unsigned char D[MAXBLOCKSIZE], A[MAXBLOCKSIZE], B[MAXBLOCKSIZE];
   unsigned char *I, *key;
   int err = CRYPT_ERROR;

   LTC_ARGCHK(pw   != NULL);
   LTC_ARGCHK(salt != NULL);
   LTC_ARGCHK(out  != NULL);

   key = XMALLOC(u * c);
   I   = XMALLOC(Plen + Slen);
   if (key == NULL || I == NULL) goto DONE;
   zeromem(key, u * c);

   for (i = 0; i < v;    i++) D[i] = purpose;              /* D - diversifier */
   for (i = 0; i < Slen; i++) I[i] = salt[i % saltlen];
   for (i = 0; i < Plen; i++) I[Slen + i] = pw[i % pwlen]; /* I = Salt || Pass */

   for (i = 0; i < c; i++) {
      Alen = sizeof(A);
      err = hash_memory_multi(hash_id, A, &Alen, D, v, I, Slen + Plen, LTC_NULL); /* A = HASH(D || I) */
      if (err != CRYPT_OK) goto DONE;
      for (j = 1; j < iterations; j++) {
         err = hash_memory(hash_id, A, Alen, A, &Alen); /* A = HASH(A) */
         if (err != CRYPT_OK) goto DONE;
      }
      /* fill buffer B with A */
      for (j = 0; j < v; j++) B[j] = A[j % Alen];
      /* B += 1 */
      for (j = v; j > 0; j--) {
         if (++B[j - 1] != 0) break;
      }
      /* I_n += B */
      for (n = 0; n < k; n++) {
         ch = 0;
         for (j = v; j > 0; j--) {
            tmp = I[n * v + j - 1] + B[j - 1] + ch;
            ch = (unsigned char)((tmp >> 8) & 0xFF);
            I[n * v + j - 1] = (unsigned char)(tmp & 0xFF);
         }
      }
      /* store derived key block */
      XMEMCPY(&key[keylen], A, Alen);
      keylen += Alen;
   }

   XMEMCPY(out, key, outlen);
   err = CRYPT_OK;
DONE:
   if (I) {
      zeromem(I, Plen + Slen);
      XFREE(I);
   }
   if (key) {
      zeromem(key, u * c);
      XFREE(key);
   }
   return err;
}

#endif
