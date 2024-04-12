/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file crypt_constants.c

  Make various constants available to dynamic languages
  like Python - Larry Bugbee, February 2013

  LB - Dec 2013 - revised to include compiler define options
  LB - Mar 2014 - added endianness and word size
*/

typedef struct {
    const char *name;
    const int value;
} crypt_constant;

#define C_STRINGIFY(s) { #s, s }

static const crypt_constant s_crypt_constants[] = {

    C_STRINGIFY(CRYPT_OK),
    C_STRINGIFY(CRYPT_ERROR),
    C_STRINGIFY(CRYPT_NOP),
    C_STRINGIFY(CRYPT_INVALID_KEYSIZE),
    C_STRINGIFY(CRYPT_INVALID_ROUNDS),
    C_STRINGIFY(CRYPT_FAIL_TESTVECTOR),
    C_STRINGIFY(CRYPT_BUFFER_OVERFLOW),
    C_STRINGIFY(CRYPT_INVALID_PACKET),
    C_STRINGIFY(CRYPT_INVALID_PRNGSIZE),
    C_STRINGIFY(CRYPT_ERROR_READPRNG),
    C_STRINGIFY(CRYPT_INVALID_CIPHER),
    C_STRINGIFY(CRYPT_INVALID_HASH),
    C_STRINGIFY(CRYPT_INVALID_PRNG),
    C_STRINGIFY(CRYPT_MEM),
    C_STRINGIFY(CRYPT_PK_TYPE_MISMATCH),
    C_STRINGIFY(CRYPT_PK_NOT_PRIVATE),
    C_STRINGIFY(CRYPT_INVALID_ARG),
    C_STRINGIFY(CRYPT_FILE_NOTFOUND),
    C_STRINGIFY(CRYPT_PK_INVALID_TYPE),
    C_STRINGIFY(CRYPT_OVERFLOW),
    C_STRINGIFY(CRYPT_PK_ASN1_ERROR),
    C_STRINGIFY(CRYPT_INPUT_TOO_LONG),
    C_STRINGIFY(CRYPT_PK_INVALID_SIZE),
    C_STRINGIFY(CRYPT_INVALID_PRIME_SIZE),
    C_STRINGIFY(CRYPT_PK_INVALID_PADDING),
    C_STRINGIFY(CRYPT_HASH_OVERFLOW),

    C_STRINGIFY(PK_PUBLIC),
    C_STRINGIFY(PK_PRIVATE),

    C_STRINGIFY(LTC_ENCRYPT),
    C_STRINGIFY(LTC_DECRYPT),

#ifdef LTC_PKCS_1
    {"LTC_PKCS_1", 1},
    /* Block types */
    C_STRINGIFY(LTC_PKCS_1_EMSA),
    C_STRINGIFY(LTC_PKCS_1_EME),

    /* Padding types */
    C_STRINGIFY(LTC_PKCS_1_V1_5),
    C_STRINGIFY(LTC_PKCS_1_OAEP),
    C_STRINGIFY(LTC_PKCS_1_PSS),
    C_STRINGIFY(LTC_PKCS_1_V1_5_NA1),
#else
    {"LTC_PKCS_1", 0},
#endif

#ifdef LTC_PADDING
    {"LTC_PADDING", 1},

    C_STRINGIFY(LTC_PAD_PKCS7),
#ifdef LTC_RNG_GET_BYTES
    C_STRINGIFY(LTC_PAD_ISO_10126),
#endif
    C_STRINGIFY(LTC_PAD_ANSI_X923),
    C_STRINGIFY(LTC_PAD_ONE_AND_ZERO),
    C_STRINGIFY(LTC_PAD_ZERO),
    C_STRINGIFY(LTC_PAD_ZERO_ALWAYS),
#else
    {"LTC_PADDING", 0},
#endif

#ifdef LTC_MRSA
    {"LTC_MRSA", 1},
#else
    {"LTC_MRSA", 0},
#endif

#ifdef LTC_MECC
    {"LTC_MECC", 1},
    C_STRINGIFY(ECC_BUF_SIZE),
    C_STRINGIFY(ECC_MAXSIZE),
#else
    {"LTC_MECC", 0},
#endif

#ifdef LTC_MDSA
    {"LTC_MDSA", 1},
    C_STRINGIFY(LTC_MDSA_DELTA),
    C_STRINGIFY(LTC_MDSA_MAX_GROUP),
    C_STRINGIFY(LTC_MDSA_MAX_MODULUS),
#else
    {"LTC_MDSA", 0},
#endif

#ifdef LTC_MILLER_RABIN_REPS
    C_STRINGIFY(LTC_MILLER_RABIN_REPS),
#endif

#ifdef LTC_DER
/* DER handling */
    {"LTC_DER", 1},
    C_STRINGIFY(LTC_ASN1_EOL),
    C_STRINGIFY(LTC_ASN1_BOOLEAN),
    C_STRINGIFY(LTC_ASN1_INTEGER),
    C_STRINGIFY(LTC_ASN1_SHORT_INTEGER),
    C_STRINGIFY(LTC_ASN1_BIT_STRING),
    C_STRINGIFY(LTC_ASN1_OCTET_STRING),
    C_STRINGIFY(LTC_ASN1_NULL),
    C_STRINGIFY(LTC_ASN1_OBJECT_IDENTIFIER),
    C_STRINGIFY(LTC_ASN1_IA5_STRING),
    C_STRINGIFY(LTC_ASN1_PRINTABLE_STRING),
    C_STRINGIFY(LTC_ASN1_UTF8_STRING),
    C_STRINGIFY(LTC_ASN1_UTCTIME),
    C_STRINGIFY(LTC_ASN1_CHOICE),
    C_STRINGIFY(LTC_ASN1_SEQUENCE),
    C_STRINGIFY(LTC_ASN1_SET),
    C_STRINGIFY(LTC_ASN1_SETOF),
    C_STRINGIFY(LTC_ASN1_RAW_BIT_STRING),
    C_STRINGIFY(LTC_ASN1_TELETEX_STRING),
    C_STRINGIFY(LTC_ASN1_GENERALIZEDTIME),
    C_STRINGIFY(LTC_ASN1_CUSTOM_TYPE),
    C_STRINGIFY(LTC_DER_MAX_RECURSION),
#else
    {"LTC_DER", 0},
#endif

#ifdef LTC_CTR_MODE
    {"LTC_CTR_MODE", 1},
    C_STRINGIFY(CTR_COUNTER_LITTLE_ENDIAN),
    C_STRINGIFY(CTR_COUNTER_BIG_ENDIAN),
    C_STRINGIFY(LTC_CTR_RFC3686),
#else
    {"LTC_CTR_MODE", 0},
#endif
#ifdef LTC_GCM_MODE
    C_STRINGIFY(LTC_GCM_MODE_IV),
    C_STRINGIFY(LTC_GCM_MODE_AAD),
    C_STRINGIFY(LTC_GCM_MODE_TEXT),
#endif

    C_STRINGIFY(LTC_MP_LT),
    C_STRINGIFY(LTC_MP_EQ),
    C_STRINGIFY(LTC_MP_GT),

    C_STRINGIFY(LTC_MP_NO),
    C_STRINGIFY(LTC_MP_YES),

    C_STRINGIFY(MAXBLOCKSIZE),
    C_STRINGIFY(TAB_SIZE),
    C_STRINGIFY(ARGTYPE),

#ifdef LTM_DESC
    {"LTM_DESC", 1},
#else
    {"LTM_DESC", 0},
#endif
#ifdef TFM_DESC
    {"TFM_DESC", 1},
#else
    {"TFM_DESC", 0},
#endif
#ifdef GMP_DESC
    {"GMP_DESC", 1},
#else
    {"GMP_DESC", 0},
#endif

#ifdef LTC_FAST
    {"LTC_FAST", 1},
#else
    {"LTC_FAST", 0},
#endif

#ifdef LTC_NO_FILE
    {"LTC_NO_FILE", 1},
#else
    {"LTC_NO_FILE", 0},
#endif

#ifdef ENDIAN_LITTLE
    {"ENDIAN_LITTLE",             1},
#else
    {"ENDIAN_LITTLE",             0},
#endif

#ifdef ENDIAN_BIG
    {"ENDIAN_BIG",                1},
#else
    {"ENDIAN_BIG",                0},
#endif

#ifdef ENDIAN_32BITWORD
    {"ENDIAN_32BITWORD",          1},
#else
    {"ENDIAN_32BITWORD",          0},
#endif

#ifdef ENDIAN_64BITWORD
    {"ENDIAN_64BITWORD",          1},
#else
    {"ENDIAN_64BITWORD",          0},
#endif

#ifdef ENDIAN_NEUTRAL
    {"ENDIAN_NEUTRAL",            1},
#else
    {"ENDIAN_NEUTRAL",            0},
#endif
};


/* crypt_get_constant()
 * valueout will be the value of the named constant
 * return -1 if named item not found
 */
int crypt_get_constant(const char* namein, int *valueout) {
    int i;
    int count = sizeof(s_crypt_constants) / sizeof(s_crypt_constants[0]);
    for (i=0; i<count; i++) {
        if (XSTRCMP(s_crypt_constants[i].name, namein) == 0) {
            *valueout = s_crypt_constants[i].value;
            return 0;
        }
    }
    return 1;
}

/* crypt_list_all_constants()
 * if names_list is NULL, names_list_size will be the minimum
 *     number of bytes needed to receive the complete names_list
 * if names_list is NOT NULL, names_list must be the addr of
 *     sufficient memory allocated into which the names_list
 *     is to be written.  Also, the value in names_list_size
 *     sets the upper bound of the number of characters to be
 *     written.
 * a -1 return value signifies insufficient space made available
 */
int crypt_list_all_constants(char *names_list, unsigned int *names_list_size) {
    int i;
    unsigned int total_len = 0;
    char *ptr;
    int number_len;
    int count = sizeof(s_crypt_constants) / sizeof(s_crypt_constants[0]);

    /* calculate amount of memory required for the list */
    for (i=0; i<count; i++) {
        number_len = snprintf(NULL, 0, "%s,%d\n", s_crypt_constants[i].name, s_crypt_constants[i].value);
        if (number_len < 0) {
          return -1;
        }
        total_len += number_len;
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
            number_len = snprintf(ptr, total_len, "%s,%d\n", s_crypt_constants[i].name, s_crypt_constants[i].value);
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

