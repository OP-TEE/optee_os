/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
   @file bcrypt.c
   bcrypt pbkdf, Steffen Jaeckel
*/
#ifdef LTC_BCRYPT

#define BCRYPT_WORDS 8
#define BCRYPT_HASHSIZE (BCRYPT_WORDS * 4)

static int s_bcrypt_hash(const unsigned char *pt,
                        const unsigned char *pass, unsigned long passlen,
                        const unsigned char *salt, unsigned long saltlen,
                              unsigned char *out,  unsigned long *outlen)
{
   symmetric_key key;
   int err, n;
   ulong32 ct[BCRYPT_WORDS];

   if ((err = blowfish_setup_with_data(pass, passlen, salt, saltlen, &key)) != CRYPT_OK) {
      return err;
   }
   for (n = 0; n < 64; ++n) {
      if ((err = blowfish_expand(salt, saltlen, NULL, 0, &key)) != CRYPT_OK) {
         return err;
      }
      if ((err = blowfish_expand(pass, passlen, NULL, 0, &key)) != CRYPT_OK) {
         return err;
      }
   }

   for (n = 0; n < BCRYPT_WORDS; ++n) {
      LOAD32H(ct[n], &pt[n*4]);
   }

   for (n = 0; n < 64; ++n) {
      blowfish_enc(ct, BCRYPT_WORDS/2, &key);
   }

   for (n = 0; n < BCRYPT_WORDS; ++n) {
      STORE32L(ct[n], &out[4 * n]);
   }
   *outlen = sizeof(ct);
#ifdef LTC_CLEAN_STACK
   zeromem(&key, sizeof(key));
   zeromem(ct, sizeof(ct));
#endif

   return CRYPT_OK;
}

static int s_bcrypt_pbkdf_hash(const unsigned char *pass, unsigned long passlen,
                         const unsigned char *salt, unsigned long saltlen,
                               unsigned char *out,  unsigned long *outlen)
{
   const unsigned char pt[] = "OxychromaticBlowfishSwatDynamite";
   return s_bcrypt_hash(pt, pass, passlen, salt, saltlen, out, outlen);
}

/**
   Compatible to bcrypt_pbkdf() as provided in OpenBSD
   @param password          The input password (or key)
   @param password_len      The length of the password (octets)
   @param salt              The salt (or nonce)
   @param salt_len          The length of the salt (octets)
   @param rounds            # of iterations desired [read specs for more]
   @param hash_idx          The index of the hash desired
   @param out               [out] The destination for this algorithm
   @param outlen            [in/out] The desired size of the algorithm output
   @return CRYPT_OK if successful
*/
int bcrypt_pbkdf_openbsd(const          void *secret, unsigned long secret_len,
                         const unsigned char *salt,   unsigned long salt_len,
                               unsigned int  rounds,            int hash_idx,
                               unsigned char *out,    unsigned long *outlen)
{
   int err;
   ulong32 blkno;
   unsigned long left, itts, x, y, hashed_pass_len, step_size, steps, dest, used_rounds;
   unsigned char *buf[3], blkbuf[4];
   unsigned char *hashed_pass;

   LTC_ARGCHK(secret != NULL);
   LTC_ARGCHK(salt   != NULL);
   LTC_ARGCHK(out    != NULL);
   LTC_ARGCHK(outlen != NULL);

   if ((secret_len == 0) || (salt_len == 0) || (*outlen == 0)) {
      return CRYPT_INVALID_ARG;
   }
   /* test hash IDX */
   if ((err = hash_is_valid(hash_idx)) != CRYPT_OK) {
      return err;
   }
   /* set default value for rounds if not given */
   if (rounds == 0) {
      used_rounds = LTC_BCRYPT_DEFAULT_ROUNDS;
   } else {
      used_rounds = rounds;
   }

   buf[0]      = XMALLOC(MAXBLOCKSIZE * 3);
   hashed_pass = XMALLOC(MAXBLOCKSIZE);
   if (buf[0] == NULL || hashed_pass == NULL) {
      if (hashed_pass != NULL) {
         XFREE(hashed_pass);
      }
      if (buf[0] != NULL) {
         XFREE(buf[0]);
      }
      return CRYPT_MEM;
   }
   /* buf[1] points to the second block of MAXBLOCKSIZE bytes */
   buf[1] = buf[0] + MAXBLOCKSIZE;
   buf[2] = buf[1] + MAXBLOCKSIZE;

   step_size = (*outlen + BCRYPT_HASHSIZE - 1) / BCRYPT_HASHSIZE;
   steps = (*outlen + step_size - 1) / step_size;

   hashed_pass_len = MAXBLOCKSIZE;
   if ((err = hash_memory(hash_idx, (unsigned char*)secret, secret_len, hashed_pass, &hashed_pass_len)) != CRYPT_OK) {
      goto LBL_ERR;
   }

   left   = *outlen;
   blkno  = 0;
   while (left != 0) {
       /* increment and store current block number */
       ++blkno;
       STORE32H(blkno, blkbuf);

       /* process block number blkno */
       zeromem(buf[0], MAXBLOCKSIZE*2);

       x = MAXBLOCKSIZE;
       if ((err = hash_memory_multi(hash_idx, buf[0], &x,
                                    salt, salt_len,
                                    blkbuf, 4uL,
                                    LTC_NULL)) != CRYPT_OK) {
          goto LBL_ERR;
       }
       y = MAXBLOCKSIZE;
       if ((err = s_bcrypt_pbkdf_hash(hashed_pass, hashed_pass_len, buf[0], x, buf[1], &y)) != CRYPT_OK) {
          goto LBL_ERR;
       }
       XMEMCPY(buf[2], buf[1], y);

       /* now compute repeated and XOR it in buf[2] */
       for (itts = 1; itts < used_rounds; ++itts) {
          x = MAXBLOCKSIZE;
          if ((err = hash_memory(hash_idx, buf[1], y, buf[0], &x)) != CRYPT_OK) {
             goto LBL_ERR;
          }
          y = MAXBLOCKSIZE;
          if ((err = s_bcrypt_pbkdf_hash(hashed_pass, hashed_pass_len, buf[0], x, buf[1], &y)) != CRYPT_OK) {
             goto LBL_ERR;
          }
          for (x = 0; x < y; x++) {
             buf[2][x] ^= buf[1][x];
          }
       }

       /* now emit upto `steps` bytes of buf[2] to output */
       steps = MIN(steps, left);
       for (y = 0; y < steps; ++y) {
          dest = y * step_size + (blkno - 1);
          if (dest >= *outlen)
             break;
          out[dest] = buf[2][y];
       }
       left -= y;
   }

   err = CRYPT_OK;
LBL_ERR:
#ifdef LTC_CLEAN_STACK
   zeromem(buf[0], MAXBLOCKSIZE*3);
   zeromem(hashed_pass, MAXBLOCKSIZE);
#endif

   XFREE(hashed_pass);
   XFREE(buf[0]);

   return err;
}

#endif

