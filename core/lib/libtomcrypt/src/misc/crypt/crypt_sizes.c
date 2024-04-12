/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file crypt_sizes.c

  Make various struct sizes available to dynamic languages
  like Python - Larry Bugbee, February 2013

  LB - Dec 2013 - revised to include compiler define options
*/


typedef struct {
    const char *name;
    const unsigned int size;
} crypt_size;

#define SZ_STRINGIFY_S(s) { #s, sizeof(struct s) }
#define SZ_STRINGIFY_T(s) { #s, sizeof(s) }

static const crypt_size s_crypt_sizes[] = {
    /* hash state sizes */
    SZ_STRINGIFY_S(ltc_hash_descriptor),
    SZ_STRINGIFY_T(hash_state),
#ifdef LTC_CHC_HASH
    SZ_STRINGIFY_S(chc_state),
#endif
#ifdef LTC_WHIRLPOOL
    SZ_STRINGIFY_S(whirlpool_state),
#endif
#ifdef LTC_SHA3
    SZ_STRINGIFY_S(sha3_state),
#endif
#ifdef LTC_SHA512
    SZ_STRINGIFY_S(sha512_state),
#endif
#ifdef LTC_SHA256
    SZ_STRINGIFY_S(sha256_state),
#endif
#ifdef LTC_SHA1
    SZ_STRINGIFY_S(sha1_state),
#endif
#ifdef LTC_MD5
    SZ_STRINGIFY_S(md5_state),
#endif
#ifdef LTC_MD4
    SZ_STRINGIFY_S(md4_state),
#endif
#ifdef LTC_MD2
    SZ_STRINGIFY_S(md2_state),
#endif
#ifdef LTC_TIGER
    SZ_STRINGIFY_S(tiger_state),
#endif
#ifdef LTC_RIPEMD128
    SZ_STRINGIFY_S(rmd128_state),
#endif
#ifdef LTC_RIPEMD160
    SZ_STRINGIFY_S(rmd160_state),
#endif
#ifdef LTC_RIPEMD256
    SZ_STRINGIFY_S(rmd256_state),
#endif
#ifdef LTC_RIPEMD320
    SZ_STRINGIFY_S(rmd320_state),
#endif
#ifdef LTC_BLAKE2S
    SZ_STRINGIFY_S(blake2s_state),
#endif
#ifdef LTC_BLAKE2B
    SZ_STRINGIFY_S(blake2b_state),
#endif

    /* block cipher key sizes */
    SZ_STRINGIFY_S(ltc_cipher_descriptor),
    SZ_STRINGIFY_T(symmetric_key),
#ifdef LTC_ANUBIS
    SZ_STRINGIFY_S(anubis_key),
#endif
#ifdef LTC_CAMELLIA
    SZ_STRINGIFY_S(camellia_key),
#endif
#ifdef LTC_BLOWFISH
    SZ_STRINGIFY_S(blowfish_key),
#endif
#ifdef LTC_CAST5
    SZ_STRINGIFY_S(cast5_key),
#endif
#ifdef LTC_DES
    SZ_STRINGIFY_S(des_key),
    SZ_STRINGIFY_S(des3_key),
#endif
#ifdef LTC_IDEA
    SZ_STRINGIFY_S(idea_key),
#endif
#ifdef LTC_KASUMI
    SZ_STRINGIFY_S(kasumi_key),
#endif
#ifdef LTC_KHAZAD
    SZ_STRINGIFY_S(khazad_key),
#endif
#ifdef LTC_KSEED
    SZ_STRINGIFY_S(kseed_key),
#endif
#ifdef LTC_MULTI2
    SZ_STRINGIFY_S(multi2_key),
#endif
#ifdef LTC_NOEKEON
    SZ_STRINGIFY_S(noekeon_key),
#endif
#ifdef LTC_RC2
    SZ_STRINGIFY_S(rc2_key),
#endif
#ifdef LTC_RC5
    SZ_STRINGIFY_S(rc5_key),
#endif
#ifdef LTC_RC6
    SZ_STRINGIFY_S(rc6_key),
#endif
#ifdef LTC_SERPENT
    SZ_STRINGIFY_S(serpent_key),
#endif
#ifdef LTC_SKIPJACK
    SZ_STRINGIFY_S(skipjack_key),
#endif
#ifdef LTC_XTEA
    SZ_STRINGIFY_S(xtea_key),
#endif
#ifdef LTC_RIJNDAEL
    SZ_STRINGIFY_S(rijndael_key),
#endif
#ifdef LTC_SAFER
    SZ_STRINGIFY_S(safer_key),
#endif
#ifdef LTC_SAFERP
    SZ_STRINGIFY_S(saferp_key),
#endif
#ifdef LTC_TWOFISH
    SZ_STRINGIFY_S(twofish_key),
#endif

    /* mode sizes */
#ifdef LTC_ECB_MODE
    SZ_STRINGIFY_T(symmetric_ECB),
#endif
#ifdef LTC_CFB_MODE
    SZ_STRINGIFY_T(symmetric_CFB),
#endif
#ifdef LTC_OFB_MODE
    SZ_STRINGIFY_T(symmetric_OFB),
#endif
#ifdef LTC_CBC_MODE
    SZ_STRINGIFY_T(symmetric_CBC),
#endif
#ifdef LTC_CTR_MODE
    SZ_STRINGIFY_T(symmetric_CTR),
#endif
#ifdef LTC_LRW_MODE
    SZ_STRINGIFY_T(symmetric_LRW),
#endif
#ifdef LTC_F8_MODE
    SZ_STRINGIFY_T(symmetric_F8),
#endif
#ifdef LTC_XTS_MODE
    SZ_STRINGIFY_T(symmetric_xts),
#endif

    /* stream cipher sizes */
#ifdef LTC_CHACHA
    SZ_STRINGIFY_T(chacha_state),
#endif
#ifdef LTC_SALSA20
    SZ_STRINGIFY_T(salsa20_state),
#endif
#ifdef LTC_SOSEMANUK
    SZ_STRINGIFY_T(sosemanuk_state),
#endif
#ifdef LTC_RABBIT
    SZ_STRINGIFY_T(rabbit_state),
#endif
#ifdef LTC_RC4_STREAM
    SZ_STRINGIFY_T(rc4_state),
#endif
#ifdef LTC_SOBER128_STREAM
    SZ_STRINGIFY_T(sober128_state),
#endif

    /* MAC sizes            -- no states for ccm, lrw */
#ifdef LTC_HMAC
    SZ_STRINGIFY_T(hmac_state),
#endif
#ifdef LTC_OMAC
    SZ_STRINGIFY_T(omac_state),
#endif
#ifdef LTC_PMAC
    SZ_STRINGIFY_T(pmac_state),
#endif
#ifdef LTC_POLY1305
    SZ_STRINGIFY_T(poly1305_state),
#endif
#ifdef LTC_EAX_MODE
    SZ_STRINGIFY_T(eax_state),
#endif
#ifdef LTC_OCB_MODE
    SZ_STRINGIFY_T(ocb_state),
#endif
#ifdef LTC_OCB3_MODE
    SZ_STRINGIFY_T(ocb3_state),
#endif
#ifdef LTC_CCM_MODE
    SZ_STRINGIFY_T(ccm_state),
#endif
#ifdef LTC_GCM_MODE
    SZ_STRINGIFY_T(gcm_state),
#endif
#ifdef LTC_PELICAN
    SZ_STRINGIFY_T(pelican_state),
#endif
#ifdef LTC_XCBC
    SZ_STRINGIFY_T(xcbc_state),
#endif
#ifdef LTC_F9_MODE
    SZ_STRINGIFY_T(f9_state),
#endif
#ifdef LTC_CHACHA20POLY1305_MODE
    SZ_STRINGIFY_T(chacha20poly1305_state),
#endif

    /* asymmetric keys */
#ifdef LTC_MRSA
    SZ_STRINGIFY_T(rsa_key),
#endif
#ifdef LTC_MDSA
    SZ_STRINGIFY_T(dsa_key),
#endif
#ifdef LTC_MDH
    SZ_STRINGIFY_T(dh_key),
#endif
#ifdef LTC_MECC
    SZ_STRINGIFY_T(ltc_ecc_curve),
    SZ_STRINGIFY_T(ecc_point),
    SZ_STRINGIFY_T(ecc_key),
#endif

    /* DER handling */
#ifdef LTC_DER
    SZ_STRINGIFY_T(ltc_asn1_list),  /* a list entry */
    SZ_STRINGIFY_T(ltc_utctime),
    SZ_STRINGIFY_T(ltc_generalizedtime),
#endif

    /* prng state sizes */
    SZ_STRINGIFY_S(ltc_prng_descriptor),
    SZ_STRINGIFY_T(prng_state),
#ifdef LTC_FORTUNA
    SZ_STRINGIFY_S(fortuna_prng),
#endif
#ifdef LTC_CHACHA20_PRNG
    SZ_STRINGIFY_S(chacha20_prng),
#endif
#ifdef LTC_RC4
    SZ_STRINGIFY_S(rc4_prng),
#endif
#ifdef LTC_SOBER128
    SZ_STRINGIFY_S(sober128_prng),
#endif
#ifdef LTC_YARROW
    SZ_STRINGIFY_S(yarrow_prng),
#endif
    /* sprng has no state as it uses other potentially available sources */
    /* like /dev/random.  See Developers Guide for more info. */

#ifdef LTC_ADLER32
    SZ_STRINGIFY_T(adler32_state),
#endif
#ifdef LTC_CRC32
    SZ_STRINGIFY_T(crc32_state),
#endif

    SZ_STRINGIFY_T(ltc_mp_digit),
    SZ_STRINGIFY_T(ltc_math_descriptor)

};

/* crypt_get_size()
 * sizeout will be the size (bytes) of the named struct or union
 * return -1 if named item not found
 */
int crypt_get_size(const char* namein, unsigned int *sizeout) {
    int i;
    int count = sizeof(s_crypt_sizes) / sizeof(s_crypt_sizes[0]);
    for (i=0; i<count; i++) {
        if (XSTRCMP(s_crypt_sizes[i].name, namein) == 0) {
            *sizeout = s_crypt_sizes[i].size;
            return 0;
        }
    }
    return -1;
}

/* crypt_list_all_sizes()
 * if names_list is NULL, names_list_size will be the minimum
 *     size needed to receive the complete names_list
 * if names_list is NOT NULL, names_list must be the addr with
 *     sufficient memory allocated into which the names_list
 *     is to be written.  Also, the value in names_list_size
 *     sets the upper bound of the number of characters to be
 *     written.
 * a -1 return value signifies insufficient space made available
 */
int crypt_list_all_sizes(char *names_list, unsigned int *names_list_size) {
    int i;
    unsigned int total_len = 0;
    char *ptr;
    int number_len;
    int count = sizeof(s_crypt_sizes) / sizeof(s_crypt_sizes[0]);

    /* calculate amount of memory required for the list */
    for (i=0; i<count; i++) {
        number_len = snprintf(NULL, 0, "%s,%u\n", s_crypt_sizes[i].name, s_crypt_sizes[i].size);
        if (number_len < 0) {
          return -1;
        }
        total_len += number_len;
        /* this last +1 is for newlines (and ending NULL) */
    }

    if (names_list == NULL) {
        *names_list_size = total_len;
    } else {
        if (total_len > *names_list_size) {
            return -1;
        }
        /* build the names list */
        ptr = names_list;
        for (i=0; i<count; i++) {
            number_len = snprintf(ptr, total_len, "%s,%u\n", s_crypt_sizes[i].name, s_crypt_sizes[i].size);
            if (number_len < 0) return -1;
            if ((unsigned int)number_len > total_len) return -1;
            total_len -= number_len;
            ptr += number_len;
        }
        /* to remove the trailing new-line */
        ptr -= 1;
        *ptr = 0;
    }
    return 0;
}

