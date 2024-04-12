/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file ec25519_crypto_ctx.c
  curve25519 crypto context helper
*/

#ifdef LTC_CURVE25519

int ec25519_crypto_ctx(unsigned char *out, unsigned long *outlen, unsigned char flag, const unsigned char *ctx, unsigned long ctxlen)
{
  unsigned char *buf = out;

  const char *prefix = "SigEd25519 no Ed25519 collisions";
  const unsigned long prefix_len = XSTRLEN(prefix);
  const unsigned char ctxlen8 = (unsigned char)ctxlen;

  if (ctxlen > 255u) return CRYPT_INPUT_TOO_LONG;
  if (*outlen < prefix_len + 2u + ctxlen) return CRYPT_BUFFER_OVERFLOW;

  XMEMCPY(buf, prefix, prefix_len);
  buf += prefix_len;
  XMEMCPY(buf, &flag, 1);
  buf++;
  XMEMCPY(buf, &ctxlen8, 1);
  buf++;

  if (ctxlen > 0u) {
    LTC_ARGCHK(ctx != NULL);
    XMEMCPY(buf, ctx, ctxlen);
    buf += ctxlen;
  }

  *outlen = buf-out;

  return CRYPT_OK;
}

#endif
