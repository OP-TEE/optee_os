/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file ed25519_verify.c
  Verify an Ed25519 signature, Steffen Jaeckel
*/

#ifdef LTC_CURVE25519

static int s_ed25519_verify(const  unsigned char *msg, unsigned long msglen,
                            const  unsigned char *sig, unsigned long siglen,
                            const  unsigned char *ctx, unsigned long ctxlen,
                                             int *stat,
                            const curve25519_key *public_key)
{
   unsigned char* m;
   unsigned long long mlen;
   int err;

   LTC_ARGCHK(msg        != NULL);
   LTC_ARGCHK(sig        != NULL);
   LTC_ARGCHK(stat       != NULL);
   LTC_ARGCHK(public_key != NULL);

   *stat = 0;

   if (siglen != 64uL) return CRYPT_INVALID_ARG;
   if (public_key->algo != LTC_OID_ED25519) return CRYPT_PK_INVALID_TYPE;

   mlen = msglen + siglen;
   if ((mlen < msglen) || (mlen < siglen)) return CRYPT_OVERFLOW;

   m = XMALLOC(mlen);
   if (m == NULL) return CRYPT_MEM;

   XMEMCPY(m, sig, siglen);
   XMEMCPY(m + siglen, msg, msglen);

   err = tweetnacl_crypto_sign_open(stat,
                                    m, &mlen,
                                    m, mlen,
                                    ctx, ctxlen,
                                    public_key->pub);

#ifdef LTC_CLEAN_STACK
   zeromem(m, msglen + siglen);
#endif
   XFREE(m);

   return err;
}

/**
   Verify an Ed25519ctx signature.
   @param msg             [in] The data to be verified
   @param msglen          [in] The size of the data to be verified
   @param sig             [in] The signature to be verified
   @param siglen          [in] The size of the signature to be verified
   @param ctx             [in] The context
   @param ctxlen          [in] The size of the context
   @param stat            [out] The result of the signature verification, 1==valid, 0==invalid
   @param public_key      [in] The public Ed25519 key in the pair
   @return CRYPT_OK if successful
*/
int ed25519ctx_verify(const  unsigned char *msg, unsigned long msglen,
                      const  unsigned char *sig, unsigned long siglen,
                      const  unsigned char *ctx, unsigned long ctxlen,
                                       int *stat,
                      const curve25519_key *public_key)
{
   unsigned char ctx_prefix[292];
   unsigned long ctx_prefix_size = sizeof(ctx_prefix);

   LTC_ARGCHK(ctx != NULL);

   if (ec25519_crypto_ctx(ctx_prefix, &ctx_prefix_size, 0, ctx, ctxlen) != CRYPT_OK)
      return CRYPT_INVALID_ARG;

   return s_ed25519_verify(msg, msglen, sig, siglen, ctx_prefix, ctx_prefix_size, stat, public_key);
}

/**
   Verify an Ed25519ph signature.
   @param msg             [in] The data to be verified
   @param msglen          [in] The size of the data to be verified
   @param sig             [in] The signature to be verified
   @param siglen          [in] The size of the signature to be verified
   @param ctx             [in] The context
   @param ctxlen          [in] The size of the context
   @param stat            [out] The result of the signature verification, 1==valid, 0==invalid
   @param public_key      [in] The public Ed25519 key in the pair
   @return CRYPT_OK if successful
*/
int ed25519ph_verify(const  unsigned char *msg, unsigned long msglen,
                     const  unsigned char *sig, unsigned long siglen,
                     const  unsigned char *ctx, unsigned long ctxlen,
                                      int *stat,
                     const curve25519_key *public_key)
{
   int err;
   unsigned char msg_hash[64];
   unsigned char ctx_prefix[292];
   unsigned long ctx_prefix_size = sizeof(ctx_prefix);

   if ((err = ec25519_crypto_ctx(ctx_prefix, &ctx_prefix_size, 1, ctx, ctxlen)) != CRYPT_OK)
      return err;

   if ((err = tweetnacl_crypto_ph(msg_hash, msg, msglen)) != CRYPT_OK)
      return err;

   return s_ed25519_verify(msg_hash, sizeof(msg_hash), sig, siglen, ctx_prefix, ctx_prefix_size, stat, public_key);
}

/**
   Verify an Ed25519 signature.
   @param msg             [in] The data to be verified
   @param msglen          [in] The size of the data to be verified
   @param sig             [in] The signature to be verified
   @param siglen          [in] The size of the signature to be verified
   @param stat            [out] The result of the signature verification, 1==valid, 0==invalid
   @param public_key      [in] The public Ed25519 key in the pair
   @return CRYPT_OK if successful
*/
int ed25519_verify(const  unsigned char *msg, unsigned long msglen,
                   const  unsigned char *sig, unsigned long siglen,
                                    int *stat,
                   const curve25519_key *public_key)
{
   return s_ed25519_verify(msg, msglen, sig, siglen, NULL, 0, stat, public_key);
}

#endif
