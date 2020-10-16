// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2018-2021 NXP
 *
 * CAAM Prime Numbering.
 * Implementation of Prime Number functions
 */
#include <caam_common.h>
#include <caam_desc_ccb_defines.h>
#include <caam_jr.h>
#include <caam_utils_mem.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <string.h>
#include <tee_api_types.h>
#include <tee/cache.h>

#include "local.h"

#define RSA_MAX_TRIES_PRIMES 100
#define MAX_RETRY_PRIME_GEN  1000

#define RSA_TRY_FAIL	0x42
#define RETRY_TOO_SMALL 0x2A

#define STATUS_GOOD_Q   0xCA

#define MR_PRIME_SIZE 1536

#ifdef CFG_CAAM_64BIT
#define SETUP_RSA_DESC_ENTRIES   20
#define GEN_RSA_DESC_ENTRIES     62
#define CHECK_P_Q_DESC_ENTRIES   32
#else
#define SETUP_RSA_DESC_ENTRIES   17
#define GEN_RSA_DESC_ENTRIES     58
#define CHECK_P_Q_DESC_ENTRIES   29
#endif

/*
 * Predefined const value corresponding to the
 * operation sqrt(2) * (2 ^ ((nlen / 2) - 1))
 * Used at step 4.4
 */
static const uint8_t sqrt_value[] = {
	0xb5, 0x04, 0xf3, 0x33, 0xf9, 0xde, 0x64, 0x84, 0x59, 0x7d, 0x89, 0xb3,
	0x75, 0x4a, 0xbe, 0x9f, 0x1d, 0x6f, 0x60, 0xba, 0x89, 0x3b, 0xa8, 0x4c,
	0xed, 0x17, 0xac, 0x85, 0x83, 0x33, 0x99, 0x15, 0x4a, 0xfc, 0x83, 0x04,
	0x3a, 0xb8, 0xa2, 0xc3, 0xa8, 0xb1, 0xfe, 0x6f, 0xdc, 0x83, 0xdb, 0x39,
	0x0f, 0x74, 0xa8, 0x5e, 0x43, 0x9c, 0x7b, 0x4a, 0x78, 0x04, 0x87, 0x36,
	0x3d, 0xfa, 0x27, 0x68, 0xd2, 0x20, 0x2e, 0x87, 0x42, 0xaf, 0x1f, 0x4e,
	0x53, 0x05, 0x9c, 0x60, 0x11, 0xbc, 0x33, 0x7b, 0xca, 0xb1, 0xbc, 0x91,
	0x16, 0x88, 0x45, 0x8a, 0x46, 0x0a, 0xbc, 0x72, 0x2f, 0x7c, 0x4e, 0x33,
	0xc6, 0xd5, 0xa8, 0xa3, 0x8b, 0xb7, 0xe9, 0xdc, 0xcb, 0x2a, 0x63, 0x43,
	0x31, 0xf3, 0xc8, 0x4d, 0xf5, 0x2f, 0x12, 0x0f, 0x83, 0x6e, 0x58, 0x2e,
	0xea, 0xa4, 0xa0, 0x89, 0x90, 0x40, 0xca, 0x4a, 0x81, 0x39, 0x4a, 0xb6,
	0xd8, 0xfd, 0x0e, 0xfd, 0xf4, 0xd3, 0xa0, 0x2c, 0xeb, 0xc9, 0x3e, 0x0c,
	0x42, 0x64, 0xda, 0xbc, 0xd5, 0x28, 0xb6, 0x51, 0xb8, 0xcf, 0x34, 0x1b,
	0x6f, 0x82, 0x36, 0xc7, 0x01, 0x04, 0xdc, 0x01, 0xfe, 0x32, 0x35, 0x2f,
	0x33, 0x2a, 0x5e, 0x9f, 0x7b, 0xda, 0x1e, 0xbf, 0xf6, 0xa1, 0xbe, 0x3f,
	0xca, 0x22, 0x13, 0x07, 0xde, 0xa0, 0x62, 0x41, 0xf7, 0xaa, 0x81, 0xc2,
	0xc1, 0xfc, 0xbd, 0xde, 0xa2, 0xf7, 0xdc, 0x33, 0x18, 0x83, 0x8a, 0x2e,
	0xaf, 0xf5, 0xf3, 0xb2, 0xd2, 0x4f, 0x4a, 0x76, 0x3f, 0xac, 0xb8, 0x82,
	0xfd, 0xfe, 0x17, 0x0f, 0xd3, 0xb1, 0xf7, 0x80, 0xf9, 0xac, 0xce, 0x41,
	0x79, 0x7f, 0x28, 0x05, 0xc2, 0x46, 0x78, 0x5e, 0x92, 0x95, 0x70, 0x23,
	0x5f, 0xcf, 0x8f, 0x7b, 0xca, 0x3e, 0xa3, 0x3b, 0x4d, 0x7c, 0x60, 0xa5,
	0xe6, 0x33, 0xe3, 0xe1
};

/*
 * Speedups for prime searching
 *
 * These values are products of small primes.  Information about the product
 * preceeds it. These values have been pre-computed by the CAAM design team.
 *
 * Per Handbook of Applied Cryptography, Menezes et al, 4.4.1, one can compute
 * the percentage of non-primes weeded out by checking for small prime factors
 * in the candidates.  In the table below, "highest prime" is used for B, and
 * "%weeded" is the number of candidates which get through this
 * sieve.  As you can see, even with relatively few primes, there are
 * diminishing returns to using larger numbers of primes.
 *
 * Percentage weeded:  1 - 1.12/ln B
 *
 * These can be used to compute GCD(prime, smallprime) before the Miller
 * Rabin; this will weed out those candidates with 'small' primes before doing
 * the costly modular exponentation inside of Miller-Rabin.  (If the result is
 * not one, then the candidate has as a factor at least one of the small primes
 * in the product).
 *
 * So, where is the sweet spot for the size of the product versus the size of
 * the candidate?  Does it depend upon the size of the PKHA multiplier?  Hunt
 * time for primes takes a long time to actually compute, and what are the
 * stats for percentage of candidates that might be weeded out?  If not many,
 * then there is an extra computation.
 */
struct smallprime {
	const size_t length;
	const uint8_t *data;
};

/*     sizes     | #primes | highest prime | %weeded */
/*  bits / bytes |         |                         */
/*    64 / 8     |   15    |          53   |    72   */
static const uint8_t smallprime_8[] = {
	0xe2, 0x21, 0xf9, 0x7c, 0x30, 0xe9, 0x4e, 0x1d,
};

/*   128 / 16    |   25    |          101  |    76   */
static const uint8_t smallprime_16[] = {
	0x57, 0x97, 0xd4, 0x7c, 0x51, 0x68, 0x15, 0x49,	0xd7, 0x34, 0xe4, 0xfc,
	0x4c, 0x3e, 0xaf, 0x7f,
};

/*   256 / 32    |   43    |          193  |    79   */
static const uint8_t smallprime_32[] = {
	0xdb, 0xf0, 0x5b, 0x6f, 0x56, 0x54, 0xb3, 0xc0, 0xf5, 0x24, 0x35, 0x51,
	0x43, 0x95, 0x86, 0x88, 0x9f, 0x15, 0x58, 0x87, 0x81, 0x9a, 0xed, 0x2a,
	0xc0, 0x5b, 0x93, 0x35, 0x2b, 0xe9, 0x86, 0x77,
};

/*   384 / 48    |   59    |          281  |    80   */
static const uint8_t smallprime_48[] = {
	0x50, 0x12, 0x01, 0xcc, 0x51, 0xa4, 0x92, 0xa5, 0x44, 0xd3, 0x90, 0x0a,
	0xd4, 0xf8, 0xb3, 0x2a, 0x20, 0x3c, 0x85, 0x84, 0x06, 0xa4, 0x45, 0x7c,
	0xab, 0x0b, 0x4f, 0x80, 0x5a, 0xb1, 0x8a, 0xc6, 0xeb, 0x95, 0x72, 0xac,
	0x6e, 0x93, 0x94, 0xfa, 0x52, 0x2b, 0xff, 0xb6, 0xf4, 0x4a, 0xf2, 0xf3,
};

/*   512 / 64    |   74    |          379  |    81   */
static const uint8_t smallprime_64[] = {
	0x10, 0x6a, 0xa9, 0xfb, 0x76, 0x46, 0xfa, 0x6e, 0xb0, 0x81, 0x3c, 0x28,
	0xc5, 0xd5, 0xf0, 0x9f, 0x07, 0x7e, 0xc3, 0xba, 0x23, 0x8b, 0xfb, 0x99,
	0xc1, 0xb6, 0x31, 0xa2, 0x03, 0xe8, 0x11, 0x87, 0x23, 0x3d, 0xb1, 0x17,
	0xcb, 0xc3, 0x84, 0x05, 0x6e, 0xf0, 0x46, 0x59,	0xa4, 0xa1, 0x1d, 0xe4,
	0x9f, 0x7e, 0xcb, 0x29, 0xba, 0xda, 0x8f, 0x98, 0x0d, 0xec, 0xec, 0xe9,
	0x2e, 0x30, 0xc4, 0x8f,
};

/*   576 / 72    |   81    |          421  |    82   */
static const uint8_t smallprime_72[] = {
	0x01, 0x85, 0xdb, 0xeb, 0x2b, 0x8b, 0x11, 0xd3, 0x76, 0x33, 0xe9, 0xdc,
	0x1e, 0xec, 0x54, 0x15, 0x65, 0xc6, 0xce, 0x84, 0x31, 0xd2, 0x27, 0xee,
	0x28, 0xf0, 0x32, 0x8a, 0x60, 0xc9, 0x01, 0x18, 0xae, 0x03, 0x1c, 0xc5,
	0xa7, 0x81, 0xc8, 0x24, 0xd1, 0xf1, 0x6d, 0x25, 0xf4, 0xf0, 0xcc, 0xcf,
	0xf3, 0x5e, 0x97, 0x45, 0x79, 0x07, 0x2e, 0xc8, 0xca, 0xf1, 0xac, 0x8e,
	0xef, 0xd5, 0x56, 0x6f, 0xa1, 0x5f, 0xb9, 0x4f, 0xe3, 0x4f, 0x5d, 0x37,
};

/*   768 / 96    |  103    |          569  |    82   */
static const uint8_t smallprime_96[] = {
	0x25, 0xea, 0xc8, 0x9f, 0x8d, 0x4d, 0xa3, 0x38, 0x33, 0x7b, 0x49, 0x85,
	0x0d, 0x2d, 0x14, 0x89, 0x26, 0x63, 0x17, 0x7b, 0x40, 0x10, 0xaf, 0x3d,
	0xd2, 0x3e, 0xeb, 0x0b, 0x22, 0x8f, 0x38, 0x32, 0xff, 0xce, 0xe2, 0xe5,
	0xcb, 0xd1, 0xac, 0xc9, 0x8f, 0x47, 0xf2, 0x51, 0x87, 0x33, 0x80, 0xae,
	0x10, 0xf0, 0xff, 0xdd, 0x8e, 0x60, 0x2f, 0xfa, 0x21, 0x0f, 0x41, 0xf6,
	0x69, 0xa1, 0x57, 0x0a, 0x93, 0xc1, 0x58, 0xc1, 0xa9, 0xa8, 0x22, 0x7f,
	0xf8, 0x1a, 0x90, 0xc5, 0x63, 0x0e, 0x9c, 0x44, 0x84, 0x5c, 0x75, 0x5c,
	0x7d, 0xf3, 0x5a, 0x7d, 0x43, 0x0c, 0x67, 0x9a, 0x11, 0x57, 0x56, 0x55,
};

/*  1024 / 128   |  130    |          739  |    83   */
static const uint8_t smallprime_128[] = {
	0x02, 0xc8, 0x5f, 0xf8, 0x70, 0xf2, 0x4b, 0xe8, 0x0f, 0x62, 0xb1, 0xba,
	0x6c, 0x20, 0xbd, 0x72, 0xb8, 0x37, 0xef, 0xdf, 0x12, 0x12, 0x06, 0xd8,
	0x7d, 0xb5, 0x6b, 0x7d, 0x69, 0xfa, 0x4c, 0x02, 0x1c, 0x10, 0x7c, 0x3c,
	0xa2, 0x06, 0xfe, 0x8f, 0xa7, 0x08, 0x0e, 0xf5, 0x76, 0xef, 0xfc, 0x82,
	0xf9, 0xb1, 0x0f, 0x57, 0x50, 0x65, 0x6b, 0x77, 0x94, 0xb1, 0x6a, 0xfd,
	0x70, 0x99, 0x6e, 0x91, 0xae, 0xf6, 0xe0, 0xad, 0x15, 0xe9, 0x1b, 0x07,
	0x1a, 0xc9, 0xb2, 0x4d, 0x98, 0xb2, 0x33, 0xad, 0x86, 0xee, 0x05, 0x55,
	0x18, 0xe5, 0x8e, 0x56, 0x63, 0x8e, 0xf1, 0x8b, 0xac, 0x5c, 0x74, 0xcb,
	0x35, 0xbb, 0xb6, 0xe5, 0xda, 0xe2, 0x78, 0x3d, 0xd1, 0xc0, 0xce, 0x7d,
	0xec, 0x4f, 0xc7, 0x0e, 0x51, 0x86, 0xd4, 0x11, 0xdf, 0x36, 0x36, 0x8f,
	0x06, 0x1a, 0xa3, 0x60, 0x11, 0xf3, 0x01, 0x79,
};

/*  1088 / 184   |  136    |          787  |    83   */
static const uint8_t smallprime_184[] = {
	0x16, 0xaf, 0x5c, 0x18, 0xa2, 0xbe, 0xf8, 0xef, 0xf2, 0x27, 0x83, 0x32,
	0x18, 0x2d, 0x0f, 0xbf, 0x00, 0x38, 0xcc, 0x20, 0x51, 0x48, 0xb8, 0x3d,
	0x06, 0xe3, 0xd7, 0xd9, 0x32, 0x82, 0x8b, 0x18, 0xe1, 0x1e, 0x09, 0x40,
	0x28, 0xc7, 0xea, 0xed, 0xa3, 0x39, 0x50, 0x17, 0xe0, 0x7d, 0x8a, 0xe9,
	0xb5, 0x94, 0x06, 0x04, 0x51, 0xd0, 0x5f, 0x93, 0x08, 0x4c, 0xb4, 0x81,
	0x66, 0x3c, 0x94, 0xc6, 0xff, 0x98, 0x0d, 0xde, 0xcc, 0xdb, 0x42, 0xad,
	0x37, 0x09, 0x7f, 0x41, 0xa7, 0x83, 0x7f, 0xc9, 0x5a, 0xfe, 0x3f, 0x18,
	0xad, 0x76, 0xf2, 0x34, 0x83, 0xae, 0x94, 0x2e, 0x0f, 0x0c, 0x0b, 0xc6,
	0xe4, 0x00, 0x16, 0x12, 0x31, 0x89, 0x87, 0x2b, 0xe5, 0x8f, 0x6d, 0xfc,
	0x23, 0x9c, 0xa2, 0x8f, 0xb0, 0xcf, 0xbf, 0x96, 0x4c, 0x8f, 0x27, 0xce,
	0x05, 0xd6, 0xc7, 0x7a, 0x01, 0xf9, 0xd3, 0x32, 0x36, 0xc9, 0xd4, 0x42,
	0xad, 0x69, 0xed, 0x33,
};

/*  1536 / 192   |  182    |         1093  |    84   */
static const uint8_t smallprime_192[] = {
	0x02, 0x1b, 0xf9, 0x49, 0x70, 0x91, 0xb8, 0xc3, 0x68, 0xcc, 0x7c, 0x8e,
	0x00, 0xc1, 0x99, 0x0c, 0x60, 0x27, 0x48, 0x1b, 0x79, 0x21, 0x5a, 0xc8,
	0xa7, 0x51, 0x77, 0x49, 0xa2, 0x15, 0x13, 0x77, 0x9a, 0x99, 0x3d, 0x29,
	0x58, 0xfc, 0xb4, 0x9a, 0x73, 0x68, 0x02, 0x92, 0x68, 0x52, 0x79, 0x94,
	0xc6, 0xcc, 0x19, 0x28, 0xad, 0xd4, 0x12, 0x95, 0x96, 0x76, 0x5f, 0x4c,
	0xc3, 0x14, 0x1a, 0x04, 0x4e, 0xb1, 0xd6, 0x15, 0x78, 0x88, 0x16, 0x67,
	0x57, 0xd8, 0x61, 0x87, 0x81, 0x81, 0x30, 0x62, 0x03, 0x22, 0x67, 0x98,
	0x7d, 0xf0, 0xd4, 0x71, 0x9c, 0xd3, 0x8f, 0x1b, 0x70, 0x85, 0xfc, 0xa5,
	0x33, 0x4b, 0xe3, 0xa6, 0x00, 0x3a, 0x3c, 0xe7, 0xe1, 0x9a, 0xba, 0x55,
	0x3e, 0x80, 0xcc, 0x5a, 0xe4, 0x06, 0x0e, 0xff, 0x6e, 0x18, 0x06, 0x66,
	0x1d, 0xa5, 0xee, 0xb7, 0xd1, 0x42, 0xd3, 0xb2, 0xe4, 0x07, 0x39, 0xf1,
	0x44, 0x3d, 0xee, 0x3a, 0x19, 0x86, 0x37, 0xf0, 0x3c, 0x06, 0x28, 0x45,
	0xea, 0xff, 0x3f, 0xf2, 0x7e, 0xa3, 0x8d, 0x93, 0x44, 0xd8, 0xa9, 0x02,
	0x22, 0x47, 0x2d, 0xf0, 0x7d, 0xfb, 0x5c, 0x9c, 0x8a, 0xda, 0x77, 0xcd,
	0x0d, 0x5b, 0x94, 0xef, 0xf0, 0x21, 0xe0, 0x2e, 0x30, 0x7d, 0x08, 0x01,
	0x03, 0x12, 0xd5, 0x7c, 0xb5, 0xd9, 0x75, 0x76, 0x46, 0x97, 0x84, 0x2d,
};

/*  2048 / 256   |  232    |         1471  |    85   */
static const uint8_t smallprime_256[] = {
	0x24, 0x65, 0xa7, 0xbd, 0x85, 0x01, 0x1e, 0x1c, 0x9e, 0x05, 0x27, 0x92,
	0x9f, 0xff, 0x26, 0x8c, 0x82, 0xef, 0x7e, 0xfa, 0x41, 0x68, 0x63, 0xba,
	0xa5, 0xac, 0xdb, 0x09, 0x71, 0xdb, 0xa0, 0xcc, 0xac, 0x3e, 0xe4, 0x99,
	0x93, 0x45, 0x02, 0x9f, 0x2c, 0xf8, 0x10, 0xb9, 0x9e, 0x40, 0x6a, 0xac,
	0x5f, 0xce, 0x5d, 0xd6, 0x9d, 0x1c, 0x71, 0x7d, 0xae, 0xa5, 0xd1, 0x8a,
	0xb9, 0x13, 0xf4, 0x56, 0x50, 0x56, 0x79, 0xbc, 0x91, 0xc5, 0x7d, 0x46,
	0xd9, 0x88, 0x88, 0x57, 0x86, 0x2b, 0x36, 0xe2, 0xed, 0xe2, 0xe4, 0x73,
	0xc1, 0xf0, 0xab, 0x35, 0x9d, 0xa2, 0x52, 0x71, 0xaf, 0xfe, 0x15, 0xff,
	0x24, 0x0e, 0x29, 0x9d, 0x0b, 0x04, 0xf4, 0xcd, 0x0e, 0x4d, 0x7c, 0x0e,
	0x47, 0xb1, 0xa7, 0xba, 0x00, 0x7d, 0xe8, 0x9a, 0xae, 0x84, 0x8f, 0xd5,
	0xbd, 0xcd, 0x7f, 0x98, 0x15, 0x56, 0x4e, 0xb0, 0x60, 0xae, 0x14, 0xf1,
	0x9c, 0xb5, 0x0c, 0x29, 0x1f, 0x0b, 0xbd, 0x8e, 0xd1, 0xc4, 0xc7, 0xf8,
	0xfc, 0x5f, 0xba, 0x51, 0x66, 0x20, 0x01, 0x93, 0x9b, 0x53, 0x2d, 0x92,
	0xda, 0xc8, 0x44, 0xa8, 0x43, 0x1d, 0x40, 0x0c, 0x83, 0x2d, 0x03, 0x9f,
	0x5f, 0x90, 0x0b, 0x27, 0x8a, 0x75, 0x21, 0x9c, 0x29, 0x86, 0x14, 0x0c,
	0x79, 0x04, 0x5d, 0x77, 0x59, 0x54, 0x08, 0x54, 0xc3, 0x15, 0x04, 0xdc,
	0x56, 0xf1, 0xdf, 0x5e, 0xeb, 0xe7, 0xbe, 0xe4, 0x47, 0x65, 0x8b, 0x91,
	0x7b, 0xf6, 0x96, 0xd6, 0x92, 0x7f, 0x2e, 0x24, 0x28, 0xfb, 0xeb, 0x34,
	0x0e, 0x51, 0x5c, 0xb9, 0x83, 0x5d, 0x63, 0x87, 0x1b, 0xe8, 0xbb, 0xe0,
	0x9c, 0xf1, 0x34, 0x45, 0x79, 0x9f, 0x2e, 0x67, 0x78, 0x81, 0x51, 0x57,
	0x1a, 0x93, 0xb4, 0xc1, 0xee, 0xe5, 0x5d, 0x1b, 0x90, 0x72, 0xe0, 0xb2,
	0xf5, 0xc4, 0x60, 0x7f,
};

/*  3072 / 384   | 326     |          2179  |    85   */
static const uint8_t smallprime_384[] = {
	0x00, 0x4d, 0xc2, 0x0e, 0x27, 0x31, 0x51, 0x23, 0xfd, 0xab, 0xcd, 0x18,
	0xca, 0x81, 0x2e, 0xe0, 0xee, 0x44, 0x49, 0x23, 0x87, 0x38, 0x9e, 0xd6,
	0xc9, 0x16, 0x97, 0x95, 0x89, 0x65, 0xed, 0xc5, 0x3d, 0x89, 0x13, 0xa8,
	0xe6, 0xec, 0x7f, 0x83, 0x6a, 0x8b, 0xd6, 0x03, 0x7e, 0x57, 0xed, 0x0c,
	0x69, 0x30, 0xef, 0x26, 0x49, 0x0d, 0xc3, 0x5d, 0x05, 0xd0, 0x98, 0xa4,
	0x66, 0xad, 0xf8, 0x17, 0x9f, 0x82, 0x99, 0x69, 0xd1, 0x39, 0x55, 0x8f,
	0x16, 0xe9, 0x8b, 0x3f, 0x76, 0xfc, 0x90, 0x62, 0xc1, 0x57, 0x25, 0xce,
	0x09, 0x88, 0xfa, 0xed, 0xca, 0x96, 0x6a, 0x6b, 0x92, 0x5f, 0x9b, 0x9c,
	0x67, 0x03, 0x43, 0xea, 0x7e, 0x84, 0x20, 0x65, 0xbd, 0x26, 0xf2, 0xbf,
	0x29, 0x90, 0x4f, 0xa7, 0xf4, 0x9f, 0x33, 0x49, 0x28, 0x96, 0x33, 0x73,
	0xba, 0x08, 0x95, 0x96, 0x51, 0x3d, 0xac, 0xa7, 0x39, 0x28, 0xcf, 0x30,
	0x5a, 0xdf, 0x8c, 0x24, 0x6e, 0x1d, 0x99, 0xa2, 0x42, 0xd9, 0x23, 0x56,
	0x23, 0xc4, 0x9a, 0xf2, 0x91, 0x45, 0x06, 0xc9, 0x11, 0x21, 0x5e, 0x1e,
	0x49, 0xaf, 0x84, 0x80, 0x3e, 0xd9, 0xa2, 0xca, 0x05, 0x51, 0x72, 0x1f,
	0xe6, 0x31, 0x9b, 0xf2, 0x38, 0xc0, 0x8a, 0xae, 0x6f, 0xd5, 0x01, 0x54,
	0x03, 0xd9, 0xe5, 0x55, 0x09, 0xee, 0x31, 0xc9, 0x60, 0x12, 0xf9, 0x08,
	0x35, 0x18, 0x5f, 0x31, 0xcb, 0xd2, 0xe4, 0x89, 0x83, 0x3c, 0x1d, 0x54,
	0x62, 0xfa, 0x80, 0x53, 0x59, 0x04, 0x86, 0x7b, 0x2c, 0x94, 0x5e, 0x9a,
	0x0c, 0x2f, 0x7a, 0xa3, 0x6e, 0x0a, 0xc0, 0xeb, 0x9b, 0xb4, 0xc1, 0x1b,
	0xf5, 0x80, 0xcf, 0x0d, 0x6d, 0x2a, 0x49, 0xed, 0x1a, 0x2d, 0x74, 0xca,
	0xe0, 0xf4, 0xc3, 0xad, 0xff, 0x61, 0xd6, 0x48, 0xca, 0x6a, 0x12, 0x08,
	0x58, 0xf4, 0xab, 0xb3, 0xb3, 0x12, 0x07, 0xcf, 0x9b, 0x7c, 0x2f, 0xda,
	0x74, 0xf7, 0x72, 0x2b, 0x14, 0x99, 0x17, 0x87, 0x5a, 0xac, 0x9d, 0x61,
	0x53, 0xc9, 0x71, 0x13, 0xfc, 0xd3, 0x74, 0xaf, 0x93, 0xdd, 0x3f, 0xa2,
	0x1a, 0x7d, 0xe5, 0x1f, 0x1a, 0x70, 0xc6, 0x31, 0xba, 0x6c, 0x92, 0x26,
	0x1e, 0x89, 0x54, 0x1a, 0xa4, 0x71, 0x41, 0xf4, 0x4e, 0x07, 0x5a, 0x1c,
	0x52, 0x2a, 0xe5, 0x81, 0x60, 0xda, 0xc8, 0x70, 0xdf, 0xbd, 0x86, 0x06,
	0xe4, 0xec, 0xa0, 0x89, 0x2a, 0xe5, 0x1c, 0x87, 0x34, 0xf5, 0xb7, 0x71,
	0x2b, 0xcd, 0x3d, 0xe3, 0x32, 0x5e, 0xc2, 0x5f, 0x07, 0xd4, 0xef, 0x94,
	0x33, 0x94, 0xd5, 0xe7, 0xb3, 0x84, 0x10, 0x05, 0xa3, 0xbd, 0x1a, 0x3e,
	0x4d, 0x27, 0x06, 0x1d, 0x54, 0xd2, 0x44, 0x58, 0x24, 0xf8, 0x51, 0x17,
	0xd0, 0xf6, 0x97, 0x12, 0x84, 0xa8, 0xc9, 0x7a, 0x42, 0x50, 0xb9, 0x9b,
};

/*  4096 / 512   | 417     |          2887  |    86   */
static const uint8_t smallprime_512[] = {
	0x09, 0x62, 0x07, 0xfc, 0xcb, 0x19, 0xd6, 0x75, 0x8e, 0x37, 0x4b, 0xee,
	0x6c, 0x37, 0x09, 0xaf, 0x0a, 0x54, 0xa9, 0x82, 0xbf, 0x90, 0x14, 0xe4,
	0x50, 0xb7, 0x48, 0x18, 0x13, 0xb7, 0x30, 0x5b, 0x4c, 0x25, 0xf0, 0xe2,
	0xea, 0x6e, 0x2b, 0x56, 0xf9, 0x1e, 0x59, 0x92, 0x14, 0x2d, 0x21, 0x6e,
	0xae, 0xb2, 0xec, 0xe0, 0x05, 0xfa, 0x0d, 0x18, 0xef, 0xeb, 0x78, 0xef,
	0xc3, 0x41, 0xf3, 0x1f, 0x78, 0x3e, 0xe4, 0x4a, 0xc5, 0xef, 0x5d, 0xfe,
	0x35, 0x57, 0x91, 0x28, 0x21, 0x06, 0x15, 0x6c, 0x64, 0xd1, 0x67, 0xa5,
	0x42, 0x1c, 0xfe, 0xc3, 0x3c, 0xbb, 0xd3, 0x88, 0x38, 0x0b, 0xe8, 0x54,
	0x14, 0x9f, 0xb6, 0x5c, 0x08, 0xe7, 0x9c, 0xd0, 0x4e, 0xc4, 0x8b, 0x45,
	0x62, 0x8e, 0xe6, 0x7f, 0x5c, 0x6f, 0xb0, 0x18, 0x18, 0xfa, 0x1f, 0xf7,
	0x32, 0x24, 0x0c, 0x0b, 0xb1, 0xc7, 0xfe, 0xc1, 0x4c, 0x48, 0x23, 0x4c,
	0x6f, 0xc3, 0xe0, 0x75, 0x76, 0x4f, 0x63, 0xc0, 0x26, 0x83, 0x61, 0x83,
	0x1d, 0x89, 0x60, 0xf2, 0x4b, 0x23, 0x7e, 0x96, 0xc2, 0xca, 0xba, 0x4c,
	0x1a, 0x21, 0x23, 0xff, 0x33, 0xa4, 0x9b, 0xca, 0x39, 0x49, 0xe8, 0xab,
	0xad, 0xde, 0x06, 0xda, 0xc5, 0x70, 0x3d, 0x16, 0xdb, 0x76, 0x77, 0xdf,
	0x2b, 0x0c, 0xe2, 0xc7, 0x84, 0x85, 0xeb, 0xd5, 0xe6, 0x9b, 0xd8, 0x0a,
	0x18, 0x48, 0xa9, 0xfe, 0x28, 0x9c, 0xa2, 0xba, 0x66, 0x4a, 0x68, 0x7b,
	0x3f, 0x05, 0x40, 0x15, 0x6e, 0x67, 0xae, 0x67, 0x69, 0xc0, 0x9e, 0x11,
	0xce, 0x56, 0x73, 0x57, 0xf5, 0xa5, 0x76, 0xa4, 0x8e, 0xed, 0xd9, 0x63,
	0x35, 0xe6, 0x28, 0x77, 0xc7, 0x3a, 0x65, 0x40, 0x8b, 0x71, 0x48, 0x4e,
	0xd0, 0xf1, 0x1d, 0x20, 0xd5, 0x1e, 0x8e, 0x54, 0x67, 0xa1, 0xe4, 0xc0,
	0x9b, 0xf7, 0x29, 0xba, 0x16, 0x9f, 0xcf, 0xdb, 0xa8, 0xb5, 0x5c, 0x4c,
	0x5b, 0x68, 0x2f, 0xaa, 0x28, 0x71, 0x9b, 0x9f, 0x49, 0xbf, 0x36, 0x2d,
	0x9f, 0x03, 0xee, 0x6b, 0xde, 0x79, 0x01, 0xe9, 0x40, 0xe2, 0x49, 0xb4,
	0x1c, 0x93, 0xb9, 0xab, 0x05, 0x4a, 0xbc, 0xab, 0x10, 0x9a, 0xf1, 0x2a,
	0xa6, 0x53, 0x5e, 0xd8, 0xf6, 0x23, 0xab, 0xfd, 0x31, 0x2a, 0xaa, 0x08,
	0x4a, 0x74, 0x8f, 0x86, 0x53, 0x83, 0xbc, 0xe3, 0x15, 0xdc, 0x0d, 0x45,
	0xcb, 0x89, 0x50, 0x8d, 0xec, 0xa9, 0x3b, 0xda, 0x22, 0xf0, 0xe7, 0x7a,
	0x4f, 0xea, 0xa2, 0xa7, 0x90, 0xe0, 0x0e, 0x5a, 0xda, 0x9b, 0xbb, 0x9a,
	0xe7, 0xd5, 0xfb, 0x63, 0x54, 0xa2, 0x52, 0xda, 0x7d, 0xc2, 0x6e, 0x6a,
	0xc2, 0xd7, 0xa6, 0x42, 0xea, 0xbf, 0x48, 0x12, 0xe6, 0x4a, 0xe1, 0x95,
	0xbf, 0x29, 0xcc, 0x9e, 0xe0, 0x25, 0x84, 0xb7, 0x74, 0xdc, 0xb1, 0x12,
	0x91, 0x57, 0xbf, 0x52, 0x43, 0x8f, 0xb7, 0xb7, 0xcd, 0x6a, 0x78, 0x24,
	0xa7, 0x41, 0x8b, 0xcc, 0x65, 0x83, 0x05, 0x8e, 0xc2, 0xf0, 0x69, 0x28,
	0xe4, 0x42, 0x62, 0x37, 0x98, 0xb5, 0x03, 0xf6, 0x75, 0x1d, 0xce, 0xe2,
	0xc0, 0x1f, 0x39, 0xac, 0xb0, 0xfb, 0x47, 0x8f, 0x6e, 0x8b, 0x16, 0xa3,
	0x0f, 0xe8, 0x21, 0x9b, 0x8e, 0x67, 0x04, 0xc7, 0x26, 0xb6, 0x03, 0xe1,
	0x00, 0x09, 0xf6, 0x77, 0x76, 0x46, 0x51, 0x41, 0x57, 0x0d, 0x4b, 0x4c,
	0x2a, 0x30, 0xdb, 0x84, 0x02, 0x6f, 0x93, 0x4b, 0x81, 0xf0, 0xd5, 0xe9,
	0x85, 0xc9, 0x75, 0xd6, 0xa9, 0x07, 0x5a, 0x41, 0xd4, 0x17, 0xc6, 0xd9,
	0x93, 0xcb, 0x49, 0x73, 0xcb, 0xe5, 0x12, 0xa6, 0x7d, 0xb3, 0x1f, 0x6a,
	0xec, 0x8c, 0xc3, 0xe9, 0xe5, 0xeb, 0xdc, 0x1e, 0xb7, 0xb4, 0x74, 0x54,
	0x51, 0x52, 0xa1, 0x56, 0xd5, 0xac, 0x58, 0x7d,
};

static const struct smallprime smallprimes[] = {
	{ .data = smallprime_8, .length = sizeof(smallprime_8) },
	{ .data = smallprime_16, .length = sizeof(smallprime_16) },
	{ .data = smallprime_32, .length = sizeof(smallprime_32) },
	{ .data = smallprime_48, .length = sizeof(smallprime_48) },
	{ .data = smallprime_64, .length = sizeof(smallprime_64) },
	{ .data = smallprime_72, .length = sizeof(smallprime_72) },
	{ .data = smallprime_96, .length = sizeof(smallprime_96) },
	{ .data = smallprime_128, .length = sizeof(smallprime_128) },
	{ .data = smallprime_184, .length = sizeof(smallprime_184) },
	{ .data = smallprime_192, .length = sizeof(smallprime_192) },
	{ .data = smallprime_256, .length = sizeof(smallprime_256) },
	{ .data = smallprime_384, .length = sizeof(smallprime_384) },
	{ .data = smallprime_512, .length = sizeof(smallprime_512) },
};

/*
 * Search the small prime closed to the given input bytes size
 *
 * @size   Size in bytes
 * @prime  [out] Output predefined small prime
 */
static void search_smallprime(size_t size, struct caambuf *prime)
{
	size_t nb_elem = ARRAY_SIZE(smallprimes);
	size_t idx = 0;
	size_t psize = 0;

	for (; idx < nb_elem; idx++) {
		psize = smallprimes[idx].length;

		if (psize == size) {
			/* Found a predefined prime */
			RSA_TRACE("Found prime idx %zu", idx);
			prime->data = (uint8_t *)smallprimes[idx].data;
			prime->length = psize;
			prime->paddr = virt_to_phys(prime->data);
			break;
		}
	}
}

/*
 * Build the descriptor preparing the CAAM global variables used during the
 * prime generation
 *
 * @desc        [out] Descriptor built
 * @data         Prime generation data
 * @small_prime  Pre-generated small prime value
 * @desc_prime   Physical address of the prime generator descriptor
 */
static void do_desc_setup(uint32_t *desc, struct prime_data *data,
			  const struct caambuf *small_prime,
			  const paddr_t desc_prime)
{
	/*
	 * Referring to FIPS.186-4, B.3.3 (step 4.7)
	 * Maximum tries = 5 * (nlen / 2)
	 * Where nlen is the RSA security length in bit
	 */
	caam_desc_init(desc);
	caam_desc_add_word(desc, DESC_HEADER(0));

	caam_desc_add_word(desc, MATH(ADD, IMM_DATA, ZERO, SOL, 4));
	caam_desc_add_word(desc, 5 * (data->key_size / 2));

	/*
	 * Referring to FIPS.186-4, Table C.2
	 * Get the number Miller-Rabin test interation function
	 * of the prime number size
	 */
	caam_desc_add_word(desc, MATH(ADD, IMM_DATA, ZERO, SIL, 4));
	if (data->p->length > (MR_PRIME_SIZE / 8))
		caam_desc_add_word(desc, 0x4);
	else
		caam_desc_add_word(desc, 0x5);

	/*
	 * Preload PKHA A2 with the sqrt_value array (step 4.4)
	 * Do it once, not at each loop
	 */
	caam_desc_add_word(desc, FIFO_LD(CLASS_1, PKHA_A2, NOACTION,
					 data->p->length));
	caam_desc_add_ptr(desc, virt_to_phys((void *)sqrt_value));

	if (data->era >= 8 && small_prime->paddr) {
		/*
		 * Preload PKHA B2 with small prime predefined
		 * (preload only prime size requested)
		 *
		 * Before Era 8, the PRIME TEST function overwrites PKHA B2
		 * hence PKHA B2 must be reloaded if new prime tentative after
		 * PRIME TEST on Era < 8
		 */
		caam_desc_add_word(desc, FIFO_LD(CLASS_1, PKHA_B2, NOACTION,
						 small_prime->length));
		caam_desc_add_ptr(desc, small_prime->paddr);
	}

	/* Set the High order bit used to turn on MSB in prime candidate */
	caam_desc_add_word(desc, MATHI_OP1(SHIFT_L, ONE, 0x3F, REG2, 8));

	/* Load PKHA N Size with the prime size */
	caam_desc_add_word(desc, LD_IMM(CLASS_1, REG_PKHA_N_SIZE, 4));
	caam_desc_add_word(desc, data->p->length);

	/*
	 * Set the number of maximum tries because of generated value
	 * is too small. This value is used to not lock the system
	 * in prime number generation
	 */
	caam_desc_add_word(desc, MATH(ADD, ZERO, IMM_DATA, DPOVRD, 4));
	caam_desc_add_word(desc, MAX_RETRY_PRIME_GEN);

	/* Jump to the next descriptor desc */
	caam_desc_add_word(desc, JUMP_NOTLOCAL(CLASS_NO, ALL_COND_TRUE,
					       JMP_COND(NONE)));
	caam_desc_add_ptr(desc, desc_prime);

	RSA_DUMPDESC(desc);
	cache_operation(TEE_CACHECLEAN, (void *)sqrt_value, data->p->length);
}

/*
 * Build the descriptor generating a prime
 *
 * @desc        [out] Descriptor built
 * @data        Prime generation data
 * @small_prime Pre-generated small prime value
 * @do_prime_q  Generate Prime Q
 * @desc_next   Physical address of the next descriptor (can be NULL)
 */
static void do_desc_prime(uint32_t *desc, struct prime_data *data,
			  const struct caambuf *small_prime, bool do_prime_q,
			  const paddr_t desc_next)
{
	uint32_t desclen = 0;
	uint32_t retry_too_small = 0;
	uint32_t retry_new_number = 0;
	uint32_t retry_new_mr_failed = 0;
	uint32_t retry_mr_test = 0;

	caam_desc_init(desc);
	caam_desc_add_word(desc, DESC_HEADER(0));

	/* Setup the number of try counter = MAX (counting down) */
	caam_desc_add_word(desc, MATH(ADD, SOL, ZERO, VSOL, 4));

	retry_new_mr_failed = caam_desc_get_len(desc);
	if (data->era < 8 && small_prime->paddr) {
		/*
		 * Preload PKHA B2 with small prime predefined
		 * (preload only prime size requested)
		 */
		caam_desc_add_word(desc, FIFO_LD(CLASS_1, PKHA_B2, NOACTION,
						 small_prime->length));
		caam_desc_add_ptr(desc, small_prime->paddr);
	}

	retry_new_number = caam_desc_get_len(desc);
	/* Decrement the number of try */
	caam_desc_add_word(desc, MATH(SUB, VSOL, ONE, VSOL, 4));
	/* Exceed retry count - exit with RSA_TRY_FAIL error */
	caam_desc_add_word(desc,
			   HALT_USER(ALL_COND_TRUE, MATH_N, RSA_TRY_FAIL));

	retry_too_small = caam_desc_get_len(desc);
	/* Check internal limit on random value generation  */
	caam_desc_add_word(desc, MATH(SUB, DPOVRD, ONE, DPOVRD, 4));
	caam_desc_add_word(desc,
			   HALT_USER(ALL_COND_TRUE, MATH_Z, RETRY_TOO_SMALL));

	/*
	 * Step 4.2 - Obtain a string p of (nlen/2) bits
	 * Step 4.3 - if (p is not odd) then p = p + 1
	 */
	/* Generate 16 random bytes load into DECO fifo */
	caam_desc_add_word(desc, LD_IMM(CLASS_NO, REG_NFIFO, 4));
	caam_desc_add_word(desc, NFIFO_PAD(DECO, NFIFO_LC1, MSG, RND, 16));

	/* Get the DECO Input fifo 8 MSB and force on high bit */
	caam_desc_add_word(desc, MATH(OR, REG2, IFIFO, REG0, 8));
	/* Get the DECO Input fifo 8 LSB and force it be be odd */
	caam_desc_add_word(desc, MATH(OR, ONE, IFIFO, REG1, 8));
	/* Move the MSB and LSB into IFIFO */
	caam_desc_add_word(desc, MOVE(MATH_REG0, IFIFO, 0, 16));
	/* Send the 8 MSB into PKHA N */
	caam_desc_add_word(desc, LD_IMM(CLASS_NO, REG_NFIFO, 4));
	caam_desc_add_word(desc, NFIFO_NOPAD(C1, 0, IFIFO, PKHA_N, 8));

	/*
	 * Generate the "middle" random bytes and start them
	 * on their way into PKHA N
	 */
	caam_desc_add_word(desc, LD_IMM(CLASS_NO, REG_NFIFO, 8));
	caam_desc_add_word(desc, NFIFO_PAD(C1, 0, PKHA_N, RND, 0));
	caam_desc_add_word(desc, data->p->length - 16);

	/* And send the 8 LSB into PKHA N */
	caam_desc_add_word(desc, LD_IMM(CLASS_NO, REG_NFIFO, 4));
	caam_desc_add_word(desc, NFIFO_NOPAD(C1, NFIFO_FC1, IFIFO, PKHA_N, 8));

	/*
	 * Step 4.4 - if ((prime < (sqrt 2)(2^((nlen / 2) - 1))
	 *    ==> retry_too_small
	 */
	caam_desc_add_word(desc, PKHA_CPY_SSIZE(A2, B0));
	caam_desc_add_word(desc, PKHA_CPY_SSIZE(B0, A0));
	caam_desc_add_word(desc, PKHA_OP(MOD_AMODN, A));
	caam_desc_add_word(desc, PKHA_CPY_SSIZE(A2, B0));
	caam_desc_add_word(desc, PKHA_F2M_OP(MOD_ADD_A_B, B));

	desclen = caam_desc_get_len(desc);
	caam_desc_add_word(desc, JUMP_CNO_LOCAL(ANY_COND_FALSE,
						JMP_COND(PKHA_IS_ZERO),
						retry_too_small - desclen));

	/*
	 * Step 4.5 - Compute GCD(prime-1, e) and test if = 1 else try
	 * another candidate
	 */
	caam_desc_add_word(desc, PKHA_CPY_SSIZE(N0, A0));
	caam_desc_add_word(desc, FIFO_LD_IMM(CLASS_1, PKHA_B, NOACTION, 1));
	caam_desc_add_word(desc, 0x01);
	caam_desc_add_word(desc, PKHA_F2M_OP(MOD_ADD_A_B, B));
	caam_desc_add_word(desc, PKHA_CPY_SSIZE(B0, N0));

	caam_desc_add_word(desc,
			   FIFO_LD(CLASS_1, PKHA_A, NOACTION, data->e->length));
	caam_desc_add_ptr(desc, data->e->paddr);
	caam_desc_add_word(desc, PKHA_OP(GCD_A_N, B));

	desclen = caam_desc_get_len(desc);
	caam_desc_add_word(desc,
			   JUMP_CNO_LOCAL(ANY_COND_FALSE, JMP_COND(PKHA_GCD_1),
					  retry_new_number - desclen));

	caam_desc_add_word(desc, PKHA_CPY_SSIZE(N0, A0));
	caam_desc_add_word(desc, FIFO_LD_IMM(CLASS_1, PKHA_B, NOACTION, 1));
	caam_desc_add_word(desc, 0x01);
	caam_desc_add_word(desc, PKHA_F2M_OP(MOD_ADD_A_B, B));
	caam_desc_add_word(desc, PKHA_CPY_SSIZE(B0, N0));

	/*
	 * Step 4.5.1 - test primality
	 */
	if (small_prime->paddr) {
		caam_desc_add_word(desc, PKHA_CPY_SSIZE(B2, A0));
		caam_desc_add_word(desc, PKHA_OP(GCD_A_N, B));
		desclen = caam_desc_get_len(desc);
		caam_desc_add_word(desc,
				   JUMP_CNO_LOCAL(ANY_COND_FALSE,
						  JMP_COND(PKHA_GCD_1),
						  retry_new_number - desclen));
	}

	/* Generate 8 random bytes 'miller-rabin seed' */
	/* Load the number of Miller-Rabin test iteration */
	caam_desc_add_word(desc, MATH(ADD, SIL, ZERO, VSIL, 4));
	retry_mr_test = caam_desc_get_len(desc);
	caam_desc_add_word(desc, LD_IMM(CLASS_NO, REG_NFIFO, 8));
	caam_desc_add_word(desc, NFIFO_PAD(C1, NFIFO_FC1, PKHA_A, RND, 0));
	caam_desc_add_word(desc, data->p->length);
	caam_desc_add_word(desc, FIFO_LD_IMM(CLASS_1, PKHA_B, NOACTION, 1));
	caam_desc_add_word(desc, 0x01);
	caam_desc_add_word(desc, PKHA_OP(MR_PRIMER_TEST, B));

	desclen = caam_desc_get_len(desc);
	caam_desc_add_word(desc, JUMP_CNO_LOCAL(ANY_COND_FALSE,
						JMP_COND(PKHA_IS_PRIME),
						retry_new_mr_failed - desclen));
	caam_desc_add_word(desc, MATH(SUB, VSIL, ONE, VSIL, 4));

	desclen = caam_desc_get_len(desc);
	caam_desc_add_word(desc,
			   JUMP_CNO_LOCAL(ALL_COND_FALSE,
					  JMP_COND(MATH_N) | JMP_COND(MATH_Z),
					  retry_mr_test - desclen));

	/* Save prime generated */
	caam_desc_add_word(desc, FIFO_ST(PKHA_N, data->p->length));

	if (do_prime_q)
		caam_desc_add_ptr(desc, data->q->paddr);
	else
		caam_desc_add_ptr(desc, data->p->paddr);

	if (desc_next) {
		/* Jump to the next descriptor desc */
		caam_desc_add_word(desc, JUMP_NOTLOCAL(CLASS_NO, ALL_COND_TRUE,
						       JMP_COND(NONE)));
		caam_desc_add_ptr(desc, desc_next);
	}

	RSA_DUMPDESC(desc);
}

/*
 * Build the descriptor to check primes p and q not too closed.
 * Check the upper 100 bits with operation:
 *     |p - q| <= 2^(nlen/2-100)
 *
 * @desc        [out] Descriptor built
 * @p           Prime P
 * @max_n       Max N built with 0xFFFF...
 * @desc_new_q  Physical address to generate a new Q value
 */
static void do_checks_primes(uint32_t *desc, const struct caambuf *p,
			     const struct caambuf *max_n,
			     const paddr_t desc_new_q)
{
	const uint8_t check_len = 16; /* Check 128 bits */

	caam_desc_init(desc);
	caam_desc_add_word(desc, DESC_HEADER(0));

	/* Load prime p */
	caam_desc_add_word(desc, FIFO_LD(CLASS_1, PKHA_B, NOACTION, p->length));
	caam_desc_add_ptr(desc, p->paddr);

	/* Retrieve Q from PKHA N, previously computed */
	caam_desc_add_word(desc, PKHA_CPY_SSIZE(N0, A0));

	/* Calculate p - q, need a modulus of size prime p filled with 0xFF */
	caam_desc_add_word(desc,
			   FIFO_LD(CLASS_1, PKHA_N, NOACTION, max_n->length));
	caam_desc_add_ptr(desc, max_n->paddr);

	/* PKHA_B = p - q */
	caam_desc_add_word(desc, PKHA_OP(MOD_SUB_A_B, B));

	/* Unload PKHA register B to output Data FIFO */
	caam_desc_add_word(desc, LD_NOCLASS_IMM(REG_CHA_CTRL, 4));
	caam_desc_add_word(desc, CCTRL_ULOAD_PKHA_B);

	/* Get the first 128 bits in MATH 0 */
	caam_desc_add_word(desc, MOVE_WAIT(OFIFO, MATH_REG0, 0, check_len));

	/*
	 * We now need to trash the rest of the result.
	 * We started with 128, 192, or 256 bytes in the OFIFO before we moved
	 * check_len bytes into MATH registers.
	 */
	if (p->length > 128 + (size_t)check_len) {
		caam_desc_add_word(desc, MOVE(OFIFO, C1_CTX_REG, 0, check_len));
		caam_desc_add_word(desc, MOVE(OFIFO, C1_CTX_REG, 0,
					      (p->length - 128 - check_len)));
	} else if (p->length > check_len) {
		caam_desc_add_word(desc, MOVE(OFIFO, C1_CTX_REG, 0,
					      (p->length - check_len)));
	}

	/*
	 * In MATH registers we have the p - q value modulo 0xFFFFF...
	 * Check the upper 100 bits are either zero or one meaning
	 * q is too close to p
	 */
	/* Check first 64 bits if not 0's check if 1's */
	caam_desc_add_word(desc, MATH(ADD, ZERO, REG0, REG0, 8));
	caam_desc_add_word(desc,
			   JUMP_CNO_LOCAL(ANY_COND_FALSE, JMP_COND(MATH_Z), 6));
	/* First 64 bits are 0's, check next 36 bits */
	caam_desc_add_word(desc, MATH(AND, REG1, IMM_DATA, REG1, 8));
	caam_desc_add_word(desc, UINT32_MAX);
	caam_desc_add_word(desc, 0xF0000000);

	/* Next 36 bits are 0 */
	caam_desc_add_word(desc,
			   JUMP_CNO_LOCAL(ALL_COND_TRUE, JMP_COND(MATH_Z), 10));
	/* Exit status GOOD Q */
	caam_desc_add_word(desc, HALT_USER(ALL_COND_TRUE, NONE, STATUS_GOOD_Q));

	/* Check if 100 bits are 1's */
	caam_desc_add_word(desc, MATH(ADD, ONE, REG0, REG0, 8));
	/* Not all 1's exit status GOOD Q */
	caam_desc_add_word(desc,
			   HALT_USER(ANY_COND_FALSE, MATH_Z, STATUS_GOOD_Q));
	/* First 64 bits are 1's, check next 36 bits */
	caam_desc_add_word(desc, MATH(AND, REG1, IMM_DATA, REG1, 8));
	caam_desc_add_word(desc, UINT32_MAX);
	caam_desc_add_word(desc, SHIFT_U32(0xF, 28));

	/* Use only 4 bytes of immediate data even is operation is 8 bytes */
	caam_desc_add_word(desc, MATH(ADD, REG1, IMM_DATA, REG1, 8) | MATH_IFB);
	caam_desc_add_word(desc, SHIFT_U32(1, 28));

	/* Not all 1's exit status GOOD Q */
	caam_desc_add_word(desc,
			   HALT_USER(ANY_COND_FALSE, MATH_Z, STATUS_GOOD_Q));

	if (desc_new_q) {
		caam_desc_add_word(desc, JUMP_NOTLOCAL(CLASS_NO, ALL_COND_TRUE,
						       JMP_COND(NONE)));
		caam_desc_add_ptr(desc, desc_new_q);
	}

	RSA_DUMPDESC(desc);
}

/*
 * Run the Primes descriptor.
 *
 * @desc   Descriptor built
 * @prime  Prime generation data
 */
static enum caam_status run_primes(uint32_t *desc, struct prime_data *prime)
{
	enum caam_status retstatus = CAAM_FAILURE;
	struct caam_jobctx jobctx = {};

	cache_operation(TEE_CACHEFLUSH, prime->p->data, prime->p->length);

	if (prime->q)
		cache_operation(TEE_CACHEFLUSH, prime->q->data,
				prime->q->length);

	jobctx.desc = desc;
	retstatus = caam_jr_enqueue(&jobctx, NULL);

	if (prime->q && retstatus == CAAM_JOB_STATUS) {
		/*
		 * Expect to have a retstatus == CAAM_JOB_STATUS, where
		 * job status == STATUS_GOOD_Q
		 */
		RSA_TRACE("Check Prime Q Status 0x%08" PRIx32, jobctx.status);

		if (JRSTA_GET_HALT_USER(jobctx.status) == STATUS_GOOD_Q) {
			cache_operation(TEE_CACHEINVALIDATE, prime->p->data,
					prime->p->length);
			cache_operation(TEE_CACHEINVALIDATE, prime->q->data,
					prime->q->length);

			RSA_DUMPBUF("Prime P", prime->p->data,
				    prime->p->length);
			RSA_DUMPBUF("Prime Q", prime->q->data,
				    prime->q->length);
			retstatus = CAAM_NO_ERROR;
		}
	} else if (retstatus == CAAM_NO_ERROR && !prime->q) {
		cache_operation(TEE_CACHEINVALIDATE, prime->p->data,
				prime->p->length);

		RSA_DUMPBUF("Prime", prime->p->data, prime->p->length);
	}

	if (retstatus != CAAM_NO_ERROR) {
		RSA_TRACE("Prime Status 0x%08" PRIx32, jobctx.status);
		retstatus = CAAM_FAILURE;
	}

	return retstatus;
}

enum caam_status caam_prime_gen(struct prime_data *data)
{
	enum caam_status retstatus = CAAM_FAILURE;
	struct caambuf small_prime = { };
	struct caambuf max_n = { };
	uint32_t *all_descs = NULL;
	uint32_t *desc_p = NULL;
	uint32_t *desc_q = NULL;
	uint32_t *desc_check_p_q = NULL;
	paddr_t paddr_desc_p = 0;
	paddr_t paddr_desc_q = 0;
	paddr_t paddr_desc_check_p_q = 0;
	size_t size_all_descs = 0;
	size_t nb_tries = RSA_MAX_TRIES_PRIMES;

	/* Allocate the job used to prepare the operation */
	if (data->q) {
		size_all_descs = SETUP_RSA_DESC_ENTRIES +
				 GEN_RSA_DESC_ENTRIES * 2 +
				 CHECK_P_Q_DESC_ENTRIES;

		retstatus = caam_calloc_buf(&max_n, data->p->length + 1);
		if (retstatus != CAAM_NO_ERROR)
			goto end_gen_prime;

		/* Set the max_n with 0xFFF... to operate the check P and Q */
		memset(max_n.data, UINT8_MAX, max_n.length);
		cache_operation(TEE_CACHECLEAN, max_n.data, max_n.length);
	} else {
		size_all_descs = SETUP_RSA_DESC_ENTRIES + GEN_RSA_DESC_ENTRIES;
	}

	all_descs = caam_calloc_desc(size_all_descs);
	if (!all_descs) {
		retstatus = CAAM_OUT_MEMORY;
		goto end_gen_prime;
	}

	/* Descriptor Prime P */
	desc_p = all_descs + SETUP_RSA_DESC_ENTRIES;
	paddr_desc_p = virt_to_phys(desc_p);
	if (!paddr_desc_p) {
		retstatus = CAAM_FAILURE;
		goto end_gen_prime;
	}

	/*
	 * Search predefined prime in the small_prime list, if the
	 * small prime is not found in the list, continue anyway
	 * but prime will be probably not so strong
	 */
	search_smallprime(data->p->length, &small_prime);

	RSA_TRACE("Do prime of %zu bytes (security len %zu bits) (ERA=%" PRId8
		  ")",
		  data->p->length, data->key_size, data->era);

	do_desc_setup(all_descs, data, &small_prime, paddr_desc_p);

	if (data->q) {
		/* Descriptor Prime Q */
		desc_q = desc_p + GEN_RSA_DESC_ENTRIES;
		paddr_desc_q =
			paddr_desc_p + DESC_SZBYTES(GEN_RSA_DESC_ENTRIES);

		/* Descriptor Check Primes P & Q */
		desc_check_p_q = desc_q + GEN_RSA_DESC_ENTRIES;
		paddr_desc_check_p_q =
			paddr_desc_q + DESC_SZBYTES(GEN_RSA_DESC_ENTRIES);

		/* Generate Prime P and Q then check Q not too close than P */
		do_desc_prime(desc_p, data, &small_prime, false, paddr_desc_q);

		do_desc_prime(desc_q, data, &small_prime, true,
			      paddr_desc_check_p_q);

		do_checks_primes(desc_check_p_q, data->p, &max_n, paddr_desc_q);
	} else {
		do_desc_prime(desc_p, data, &small_prime, false, 0);
	}

	cache_operation(TEE_CACHECLEAN, small_prime.data, data->p->length);
	cache_operation(TEE_CACHECLEAN, data->e->data, data->e->length);
	cache_operation(TEE_CACHECLEAN, (void *)all_descs,
			DESC_SZBYTES(size_all_descs));

	for (retstatus = CAAM_FAILURE;
	     nb_tries > 0 && retstatus != CAAM_NO_ERROR; nb_tries--)
		retstatus = run_primes(all_descs, data);

end_gen_prime:
	caam_free_desc(&all_descs);
	caam_free_buf(&max_n);

	return retstatus;
}
