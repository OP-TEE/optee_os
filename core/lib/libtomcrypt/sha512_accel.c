// SPDX-License-Identifier: Unlicense AND BSD-2-Clause
/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* Copyright (c) 2023 Linaro Limited */
#include <crypto/crypto_accel.h>
#include <tomcrypt_private.h>

/**
   @param sha512.c
   LTC_SHA512 by Tom St Denis
*/

#ifdef LTC_SHA512

const struct ltc_hash_descriptor sha512_desc =
{
    "sha512",
    5,
    64,
    128,

    /* OID */
   { 2, 16, 840, 1, 101, 3, 4, 2, 3,  },
   9,

    &sha512_init,
    &sha512_process,
    &sha512_done,
    &sha512_test,
    NULL
};


/* Implemented in assembly */
int sha512_ce_transform(ulong64 *state, const unsigned char *buf, int blocks);

static int sha512_compress_nblocks(hash_state *md, const unsigned char *buf,
				   int blocks)
{
   void *state = md->sha512.state;

   COMPILE_TIME_ASSERT(sizeof(md->sha512.state[0]) == sizeof(uint64_t));

   crypto_accel_sha512_compress(state, buf, blocks);

   return CRYPT_OK;
}

static int sha512_compress(hash_state *md, const unsigned char *buf)
{
   return sha512_compress_nblocks(md, buf, 1);
}

/**
   Initialize the hash state
   @param md   The hash state you wish to initialize
   @return CRYPT_OK if successful
*/
int sha512_init(hash_state * md)
{
    LTC_ARGCHK(md != NULL);
    md->sha512.curlen = 0;
    md->sha512.length = 0;
    md->sha512.state[0] = CONST64(0x6a09e667f3bcc908);
    md->sha512.state[1] = CONST64(0xbb67ae8584caa73b);
    md->sha512.state[2] = CONST64(0x3c6ef372fe94f82b);
    md->sha512.state[3] = CONST64(0xa54ff53a5f1d36f1);
    md->sha512.state[4] = CONST64(0x510e527fade682d1);
    md->sha512.state[5] = CONST64(0x9b05688c2b3e6c1f);
    md->sha512.state[6] = CONST64(0x1f83d9abfb41bd6b);
    md->sha512.state[7] = CONST64(0x5be0cd19137e2179);
    return CRYPT_OK;
}

HASH_PROCESS_NBLOCKS(sha512_process, sha512_compress_nblocks, sha512, 128)

/**
   Terminate the hash to get the digest
   @param md  The hash state
   @param out [out] The destination of the hash (64 bytes)
   @return CRYPT_OK if successful
*/
int sha512_done(hash_state * md, unsigned char *out)
{
    int i;

    LTC_ARGCHK(md  != NULL);
    LTC_ARGCHK(out != NULL);

    if (md->sha512.curlen >= sizeof(md->sha512.buf)) {
       return CRYPT_INVALID_ARG;
    }

    /* increase the length of the message */
    md->sha512.length += md->sha512.curlen * CONST64(8);

    /* append the '1' bit */
    md->sha512.buf[md->sha512.curlen++] = (unsigned char)0x80;

    /* if the length is currently above 112 bytes we append zeros
     * then compress.  Then we can fall back to padding zeros and length
     * encoding like normal.
     */
    if (md->sha512.curlen > 112) {
        while (md->sha512.curlen < 128) {
            md->sha512.buf[md->sha512.curlen++] = (unsigned char)0;
        }
        sha512_compress(md, md->sha512.buf);
        md->sha512.curlen = 0;
    }

    /* pad upto 120 bytes of zeroes
     * note: that from 112 to 120 is the 64 MSB of the length.  We assume that you won't hash
     * > 2^64 bits of data... :-)
     */
    while (md->sha512.curlen < 120) {
        md->sha512.buf[md->sha512.curlen++] = (unsigned char)0;
    }

    /* store length */
    STORE64H(md->sha512.length, md->sha512.buf+120);
    sha512_compress(md, md->sha512.buf);

    /* copy output */
    for (i = 0; i < 8; i++) {
        STORE64H(md->sha512.state[i], out+(8*i));
    }
#ifdef LTC_CLEAN_STACK
    zeromem(md, sizeof(hash_state));
#endif
    return CRYPT_OK;
}

/**
  Self-test the hash
  @return CRYPT_OK if successful, CRYPT_NOP if self-tests have been disabled
*/
int  sha512_test(void)
{
 #ifndef LTC_TEST
    return CRYPT_NOP;
 #else
  static const struct {
      const char *msg;
      unsigned char hash[64];
  } tests[] = {
    { "abc",
     { 0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba,
       0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41, 0x31,
       0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2,
       0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a,
       0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8,
       0x36, 0xba, 0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd,
       0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e,
       0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f }
    },
    { "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
     { 0x8e, 0x95, 0x9b, 0x75, 0xda, 0xe3, 0x13, 0xda,
       0x8c, 0xf4, 0xf7, 0x28, 0x14, 0xfc, 0x14, 0x3f,
       0x8f, 0x77, 0x79, 0xc6, 0xeb, 0x9f, 0x7f, 0xa1,
       0x72, 0x99, 0xae, 0xad, 0xb6, 0x88, 0x90, 0x18,
       0x50, 0x1d, 0x28, 0x9e, 0x49, 0x00, 0xf7, 0xe4,
       0x33, 0x1b, 0x99, 0xde, 0xc4, 0xb5, 0x43, 0x3a,
       0xc7, 0xd3, 0x29, 0xee, 0xb6, 0xdd, 0x26, 0x54,
       0x5e, 0x96, 0xe5, 0x5b, 0x87, 0x4b, 0xe9, 0x09 }
    },
  };

  int i;
  unsigned char tmp[64];
  hash_state md;

  for (i = 0; i < (int)(sizeof(tests) / sizeof(tests[0])); i++) {
      sha512_init(&md);
      sha512_process(&md, (unsigned char *)tests[i].msg, (unsigned long)XSTRLEN(tests[i].msg));
      sha512_done(&md, tmp);
      if (compare_testvector(tmp, sizeof(tmp), tests[i].hash, sizeof(tests[i].hash), "SHA512", i)) {
         return CRYPT_FAIL_TESTVECTOR;
      }
  }
  return CRYPT_OK;
  #endif
}

#endif /*LTC_SHA512*/
