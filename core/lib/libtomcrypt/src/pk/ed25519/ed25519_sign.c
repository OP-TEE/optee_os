/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file ed25519_shared_secret.c
  Create an Ed25519 signature, Steffen Jaeckel
*/

#ifdef LTC_CURVE25519

static int s_ed25519_sign(const unsigned char  *msg, unsigned long  msglen,
                                unsigned char  *sig, unsigned long *siglen,
                          const unsigned char  *ctx, unsigned long  ctxlen,
                          const curve25519_key *private_key)
{
   unsigned char *s;
   unsigned long long smlen;
   int err;

   LTC_ARGCHK(msg         != NULL);
   LTC_ARGCHK(sig         != NULL);
   LTC_ARGCHK(siglen      != NULL);
   LTC_ARGCHK(private_key != NULL);

   if (private_key->algo != LTC_OID_ED25519) return CRYPT_PK_INVALID_TYPE;
   if (private_key->type != PK_PRIVATE) return CRYPT_PK_INVALID_TYPE;

   if (*siglen < 64uL) {
      *siglen = 64uL;
      return CRYPT_BUFFER_OVERFLOW;
   }

   smlen = msglen + 64;
   s = XMALLOC(smlen);
   if (s == NULL) return CRYPT_MEM;

   err = tweetnacl_crypto_sign(s, &smlen,
                               msg, msglen,
                               private_key->priv, private_key->pub,
                               ctx, ctxlen);

   XMEMCPY(sig, s, 64uL);
   *siglen = 64uL;

#ifdef LTC_CLEAN_STACK
   zeromem(s, smlen);
#endif
   XFREE(s);

   return err;
}

/**
   Create an Ed25519ctx signature.
   @param msg             The data to be signed
   @param msglen          [in] The size of the date to be signed
   @param sig             [out] The destination of the shared data
   @param siglen          [in/out] The max size and resulting size of the shared data.
   @param ctx             [in] The context is a constant null terminated string
   @param private_key     The private Ed25519 key in the pair
   @return CRYPT_OK if successful
*/
int ed25519ctx_sign(const  unsigned char *msg, unsigned long  msglen,
                           unsigned char *sig, unsigned long *siglen,
                    const  unsigned char *ctx, unsigned long  ctxlen,
                    const curve25519_key *private_key)
{
   int err;
   unsigned char ctx_prefix[292];
   unsigned long ctx_prefix_size = sizeof(ctx_prefix);

   LTC_ARGCHK(ctx != NULL);

   if ((err = ec25519_crypto_ctx(ctx_prefix, &ctx_prefix_size, 0, ctx, ctxlen)) != CRYPT_OK)
      return err;

   return s_ed25519_sign(msg, msglen, sig, siglen, ctx_prefix, ctx_prefix_size, private_key);
}

/**
   Create an Ed25519ph signature.
   @param msg             The data to be signed
   @param msglen          [in] The size of the date to be signed
   @param sig             [out] The destination of the shared data
   @param siglen          [in/out] The max size and resulting size of the shared data.
   @param ctx             [in] The context is a constant null terminated string
   @param private_key     The private Ed25519 key in the pair
   @return CRYPT_OK if successful
*/
int ed25519ph_sign(const  unsigned char *msg, unsigned long  msglen,
                          unsigned char *sig, unsigned long *siglen,
                   const  unsigned char *ctx, unsigned long  ctxlen,
                   const curve25519_key *private_key)
{
   int err;
   unsigned char msg_hash[64];
   unsigned char ctx_prefix[292];
   unsigned long ctx_prefix_size = sizeof(ctx_prefix);

   if ((err = ec25519_crypto_ctx(ctx_prefix, &ctx_prefix_size, 1, ctx, ctxlen)) != CRYPT_OK)
      return err;

   if ((err = tweetnacl_crypto_ph(msg_hash, msg, msglen)) != CRYPT_OK)
      return err;

   return s_ed25519_sign(msg_hash, sizeof(msg_hash), sig, siglen, ctx_prefix, ctx_prefix_size, private_key);
}

/**
   Create an Ed25519 signature.
   @param msg             The data to be signed
   @param msglen          [in] The size of the date to be signed
   @param sig             [out] The destination of the shared data
   @param siglen          [in/out] The max size and resulting size of the shared data.
   @param private_key     The private Ed25519 key in the pair
   @return CRYPT_OK if successful
*/
int ed25519_sign(const  unsigned char *msg, unsigned long msglen,
                        unsigned char *sig, unsigned long *siglen,
                 const curve25519_key *private_key)
{
   return s_ed25519_sign(msg, msglen, sig, siglen, NULL, 0, private_key);
}

#endif
