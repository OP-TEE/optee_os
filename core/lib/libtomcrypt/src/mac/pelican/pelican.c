/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
   @file pelican.c
   Pelican MAC, initialize state, by Tom St Denis
*/

#ifdef LTC_PELICAN

#define LTC_AES_TAB_C
#define ENCRYPT_ONLY
#define PELI_TAB
#include "../../ciphers/aes/aes_tab.c"

/**
   Initialize a Pelican state
   @param pelmac    The Pelican state to initialize
   @param key       The secret key
   @param keylen    The length of the secret key (octets)
   @return CRYPT_OK if successful
*/
int pelican_init(pelican_state *pelmac, const unsigned char *key, unsigned long keylen)
{
    int err;

    LTC_ARGCHK(pelmac != NULL);
    LTC_ARGCHK(key    != NULL);

#ifdef LTC_FAST
    if (16 % sizeof(LTC_FAST_TYPE)) {
        return CRYPT_INVALID_ARG;
    }
#endif

    if ((err = aes_setup(key, keylen, 0, &pelmac->K)) != CRYPT_OK) {
       return err;
    }

    zeromem(pelmac->state, 16);
    aes_ecb_encrypt(pelmac->state, pelmac->state, &pelmac->K);
    pelmac->buflen = 0;

    return CRYPT_OK;
}

static void s_four_rounds(pelican_state *pelmac)
{
    ulong32 s0, s1, s2, s3, t0, t1, t2, t3;
    int r;

    LOAD32H(s0, pelmac->state      );
    LOAD32H(s1, pelmac->state  +  4);
    LOAD32H(s2, pelmac->state  +  8);
    LOAD32H(s3, pelmac->state  + 12);
    for (r = 0; r < 4; r++) {
        t0 =
            Te0(LTC_BYTE(s0, 3)) ^
            Te1(LTC_BYTE(s1, 2)) ^
            Te2(LTC_BYTE(s2, 1)) ^
            Te3(LTC_BYTE(s3, 0));
        t1 =
            Te0(LTC_BYTE(s1, 3)) ^
            Te1(LTC_BYTE(s2, 2)) ^
            Te2(LTC_BYTE(s3, 1)) ^
            Te3(LTC_BYTE(s0, 0));
        t2 =
            Te0(LTC_BYTE(s2, 3)) ^
            Te1(LTC_BYTE(s3, 2)) ^
            Te2(LTC_BYTE(s0, 1)) ^
            Te3(LTC_BYTE(s1, 0));
        t3 =
            Te0(LTC_BYTE(s3, 3)) ^
            Te1(LTC_BYTE(s0, 2)) ^
            Te2(LTC_BYTE(s1, 1)) ^
            Te3(LTC_BYTE(s2, 0));
        s0 = t0; s1 = t1; s2 = t2; s3 = t3;
    }
    STORE32H(s0, pelmac->state      );
    STORE32H(s1, pelmac->state  +  4);
    STORE32H(s2, pelmac->state  +  8);
    STORE32H(s3, pelmac->state  + 12);
}

/**
  Process a block of text through Pelican
  @param pelmac       The Pelican MAC state
  @param in           The input
  @param inlen        The length input (octets)
  @return CRYPT_OK on success
  */
int pelican_process(pelican_state *pelmac, const unsigned char *in, unsigned long inlen)
{

   LTC_ARGCHK(pelmac != NULL);
   LTC_ARGCHK(in     != NULL);

   /* check range */
   if (pelmac->buflen < 0 || pelmac->buflen > 15) {
      return CRYPT_INVALID_ARG;
   }

#ifdef LTC_FAST
   if (pelmac->buflen == 0) {
      while (inlen & ~15) {
         int x;
         for (x = 0; x < 16; x += sizeof(LTC_FAST_TYPE)) {
            *(LTC_FAST_TYPE_PTR_CAST((unsigned char *)pelmac->state + x)) ^= *(LTC_FAST_TYPE_PTR_CAST((unsigned char *)in + x));
         }
         s_four_rounds(pelmac);
         in    += 16;
         inlen -= 16;
      }
   }
#endif

   while (inlen--) {
       pelmac->state[pelmac->buflen++] ^= *in++;
       if (pelmac->buflen == 16) {
          s_four_rounds(pelmac);
          pelmac->buflen = 0;
       }
   }
   return CRYPT_OK;
}

/**
  Terminate Pelican MAC
  @param pelmac      The Pelican MAC state
  @param out         [out] The TAG
  @return CRYPT_OK on sucess
*/
int pelican_done(pelican_state *pelmac, unsigned char *out)
{
   LTC_ARGCHK(pelmac  != NULL);
   LTC_ARGCHK(out     != NULL);

   /* check range */
   if (pelmac->buflen < 0 || pelmac->buflen > 16) {
      return CRYPT_INVALID_ARG;
   }

   if  (pelmac->buflen == 16) {
       s_four_rounds(pelmac);
       pelmac->buflen = 0;
   }
   pelmac->state[pelmac->buflen++] ^= 0x80;
   aes_ecb_encrypt(pelmac->state, out, &pelmac->K);
   aes_done(&pelmac->K);
   return CRYPT_OK;
}

#endif
