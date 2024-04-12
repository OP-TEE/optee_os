/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

#ifdef LTC_RNG_GET_BYTES
/**
   @file rng_get_bytes.c
   portable way to get secure random bits to feed a PRNG (Tom St Denis)
*/

#if defined(LTC_DEVRANDOM) && !defined(_WIN32)
/* on *NIX read /dev/random */
static unsigned long s_rng_nix(unsigned char *buf, unsigned long len,
                             void (*callback)(void))
{
#ifdef LTC_NO_FILE
    LTC_UNUSED_PARAM(callback);
    LTC_UNUSED_PARAM(buf);
    LTC_UNUSED_PARAM(len);
    return 0;
#else
    FILE *f;
    unsigned long x;
    LTC_UNUSED_PARAM(callback);
#ifdef LTC_TRY_URANDOM_FIRST
    f = fopen("/dev/urandom", "rb");
    if (f == NULL) {
       f = fopen("/dev/random", "rb");
    }
#else
    f = fopen("/dev/random", "rb");
#endif /* LTC_TRY_URANDOM_FIRST */

    if (f == NULL) {
       return 0;
    }

    /* disable buffering */
    if (setvbuf(f, NULL, _IONBF, 0) != 0) {
       fclose(f);
       return 0;
    }

    x = (unsigned long)fread(buf, 1, (size_t)len, f);
    fclose(f);
    return x;
#endif /* LTC_NO_FILE */
}

#endif /* LTC_DEVRANDOM */

#if !defined(_WIN32_WCE)

#define ANSI_RNG

static unsigned long s_rng_ansic(unsigned char *buf, unsigned long len,
                               void (*callback)(void))
{
   clock_t t1;
   int l, acc, bits, a, b;

   l = len;
   bits = 8;
   acc  = a = b = 0;
   while (len--) {
       if (callback != NULL) callback();
       while (bits--) {
          do {
             t1 = XCLOCK(); while (t1 == XCLOCK()) a ^= 1;
             t1 = XCLOCK(); while (t1 == XCLOCK()) b ^= 1;
          } while (a == b);
          acc = (acc << 1) | a;
       }
       *buf++ = acc;
       acc  = 0;
       bits = 8;
   }
   return l;
}

#endif

/* Try the Microsoft CSP */
#if defined(_WIN32) || defined(_WIN32_WCE)
#if defined(LTC_WIN32_BCRYPT)

#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")

static unsigned long s_rng_win32(unsigned char *buf, unsigned long len,
                               void (*callback)(void))
{
   LTC_UNUSED_PARAM(callback);

   return BCRYPT_SUCCESS(BCryptGenRandom(NULL, (PUCHAR)buf, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG)) ? len : 0;
}

#else

#ifndef _WIN32_WINNT
  #define _WIN32_WINNT 0x0501
#endif
#ifndef WINVER
  #define WINVER 0x0501
#endif

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h>

static unsigned long s_rng_win32(unsigned char *buf, unsigned long len,
                               void (*callback)(void))
{
   LTC_UNUSED_PARAM(callback);

   static HCRYPTPROV hProv = 0;
   if (hProv == 0) {
      HCRYPTPROV h = 0;
      if (!CryptAcquireContextW(&h, NULL, MS_DEF_PROV_W, PROV_RSA_FULL,
                                (CRYPT_VERIFYCONTEXT | CRYPT_MACHINE_KEYSET)) &&
          !CryptAcquireContextW(&h, NULL, MS_DEF_PROV_W, PROV_RSA_FULL,
                                CRYPT_VERIFYCONTEXT | CRYPT_MACHINE_KEYSET | CRYPT_NEWKEYSET)) {
         return 0;
      }
      hProv = h;
   }

   return CryptGenRandom(hProv, (DWORD)len, (BYTE *)buf) == TRUE ? len : 0;
}
#endif /* Old WIN32 versions */
#endif /* WIN32 */

/**
  Read the system RNG
  @param out       Destination
  @param outlen    Length desired (octets)
  @param callback  Pointer to void function to act as "callback" when RNG is slow.  This can be NULL
  @return Number of octets read
*/
unsigned long rng_get_bytes(unsigned char *out, unsigned long outlen,
                            void (*callback)(void))
{
   unsigned long x;

   LTC_ARGCHK(out != NULL);

#ifdef LTC_PRNG_ENABLE_LTC_RNG
   if (ltc_rng) {
      x = ltc_rng(out, outlen, callback);
      if (x != 0) {
         return x;
      }
   }
#endif

#if defined(_WIN32) || defined(_WIN32_WCE)
   x = s_rng_win32(out, outlen, callback); if (x != 0) { return x; }
#elif defined(LTC_DEVRANDOM)
   x = s_rng_nix(out, outlen, callback);   if (x != 0) { return x; }
#endif
#ifdef ANSI_RNG
   x = s_rng_ansic(out, outlen, callback); if (x != 0) { return x; }
#endif
   return 0;
}
#endif /* #ifdef LTC_RNG_GET_BYTES */
