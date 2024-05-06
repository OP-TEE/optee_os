/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file rsa_decrypt_key.c
  RSA PKCS #1 Decryption, Tom St Denis and Andreas Lange
*/

#ifdef LTC_MRSA

/**
   PKCS #1 decrypt then v1.5 or OAEP depad
   @param in          The ciphertext
   @param inlen       The length of the ciphertext (octets)
   @param out         [out] The plaintext
   @param outlen      [in/out] The max size and resulting size of the plaintext (octets)
   @param lparam      The system "lparam" value
   @param lparamlen   The length of the lparam value (octets)
   @param mgf_hash    The hash algorithm used for the MGF
   @param lparam_hash The hash algorithm used when hashing the lparam (can be -1)
   @param padding     Type of padding (LTC_PKCS_1_OAEP or LTC_PKCS_1_V1_5)
   @param stat        [out] Result of the decryption, 1==valid, 0==invalid
   @param key         The corresponding private RSA key
   @return CRYPT_OK if succcessul (even if invalid)
*/
int rsa_decrypt_key_ex(const unsigned char *in,             unsigned long  inlen,
                             unsigned char *out,            unsigned long *outlen,
                       const unsigned char *lparam,         unsigned long  lparamlen,
                             int            mgf_hash,       int            lparam_hash,
                             int            padding,
                             int           *stat,     const rsa_key       *key)
{
  unsigned long modulus_bitlen, modulus_bytelen, x;
  int           err;
  unsigned char *tmp;

  LTC_ARGCHK(in     != NULL);
  LTC_ARGCHK(out    != NULL);
  LTC_ARGCHK(outlen != NULL);
  LTC_ARGCHK(key    != NULL);
  LTC_ARGCHK(stat   != NULL);

  /* default to invalid */
  *stat = 0;

  /* valid padding? */
  if ((padding != LTC_PKCS_1_V1_5) &&
      (padding != LTC_PKCS_1_OAEP)) {
    return CRYPT_PK_INVALID_PADDING;
  }

  if (padding == LTC_PKCS_1_OAEP) {
    /* valid hash ? */
    if ((err = hash_is_valid(mgf_hash)) != CRYPT_OK) {
       return err;
    }
  }

  /* get modulus len in bits */
  modulus_bitlen = mp_count_bits( (key->N));

  /* outlen must be at least the size of the modulus */
  modulus_bytelen = mp_unsigned_bin_size( (key->N));
  if (modulus_bytelen != inlen) {
     return CRYPT_INVALID_PACKET;
  }

  /* allocate ram */
  tmp = XMALLOC(inlen);
  if (tmp == NULL) {
     return CRYPT_MEM;
  }

  /* rsa decode the packet */
  x = inlen;
  if ((err = ltc_mp.rsa_me(in, inlen, tmp, &x, PK_PRIVATE, key)) != CRYPT_OK) {
     XFREE(tmp);
     return err;
  }

  if (padding == LTC_PKCS_1_OAEP) {
    /* now OAEP decode the packet */
    err = pkcs_1_oaep_decode(tmp, x, lparam, lparamlen, modulus_bitlen, mgf_hash,
                             lparam_hash, out, outlen, stat);
  } else {
    /* now PKCS #1 v1.5 depad the packet */
    err = pkcs_1_v1_5_decode(tmp, x, LTC_PKCS_1_EME, modulus_bitlen, out, outlen, stat);
  }

  XFREE(tmp);
  return err;
}

#endif /* LTC_MRSA */
