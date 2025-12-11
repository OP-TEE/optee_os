/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2022 Xilinx, Inc.  All rights reserved.
 * Copyright (C) 2022 Foundries Ltd.
 * Copyright (C) 2023 ProvenRun S.A.S
 */

#ifndef __DRIVERS_VERSAL_TRNG_H
#define __DRIVERS_VERSAL_TRNG_H

#include <stdint.h>

/*
 * IMPORTANT: The CFG_VERSAL_RNG_{IO,V1,V2,PLM} symbols are to be treated as
 *            symbols internal to this TRNG driver and shall not be set via a
 *            platform's conf.mk or similar!
 */
#if defined(CFG_VERSAL_RNG_IO) || defined(CFG_VERSAL_RNG_V1) || \
	defined(CFG_VERSAL_RNG_V2) || defined(CFG_VERSAL_RNG_PLM)
#error "One or more CFG_VERSAL_RNG_{IO,V1,V2,PLM} symbols are already defined. \
This shall NOT be done! Definition is done automatically based on platform!"
#endif

#if !defined(PLATFORM_FLAVOR_net)
#define CFG_VERSAL_RNG_IO 1
#define CFG_VERSAL_RNG_V1 1
#else
#if defined(CFG_VERSAL_CRYPTO_DRIVER) && defined(CFG_VERSAL_PKI)
#define CFG_VERSAL_RNG_IO 1
#define CFG_VERSAL_RNG_V2 1
#endif
#define CFG_VERSAL_RNG_PLM 1
#endif

#ifdef CFG_VERSAL_RNG_IO
/* TRNG configuration  */
#define TRNG_PERS_STR_REGS	12
#define TRNG_PERS_STR_LEN	48
#define TRNG_SEED_LEN		48
#define TRNG_V2_SEED_LEN	128
#define RAND_BUF_LEN		4

/* Derivative function helper macros */
#define DF_IP_IV_LEN		4
#define DF_PAD_DATA_LEN		8
#define MAX_PRE_DF_LEN		160
#define MAX_PRE_DF_LEN_WORDS	40

enum trng_version {
	TRNG_V1 = 1,
	TRNG_V2,
};

enum trng_status {
	TRNG_UNINITIALIZED = 0,
	TRNG_HEALTHY,
	TRNG_ERROR,
	TRNG_CATASTROPHIC
};

enum trng_mode {
	TRNG_HRNG = 0,
	TRNG_DRNG,
	TRNG_PTRNG
};

struct trng_cfg {
	paddr_t base;
	vaddr_t addr;
	size_t len;
	enum trng_version version;
};

struct trng_usr_cfg {
	enum trng_mode mode;
	uint64_t seed_life;      /* number of TRNG requests per seed */
	bool predict_en;         /* enable prediction resistance     */
	bool pstr_en;            /* enable personalization string    */
	uint32_t pstr[TRNG_PERS_STR_REGS];
	bool iseed_en;           /* enable an initial seed           */
	uint32_t init_seed[MAX_PRE_DF_LEN_WORDS];
	uint32_t df_disable;     /* disable the derivative function  */
	uint32_t dfmul;          /* derivative function multiplier   */
};

struct trng_stats {
	uint64_t bytes;
	uint64_t bytes_reseed;
	uint64_t elapsed_seed_life;
};

/* block cipher derivative function algorithm */
struct trng_dfin {
	uint32_t ivc[DF_IP_IV_LEN];
	uint32_t val1;
	uint32_t val2;
	uint8_t entropy[MAX_PRE_DF_LEN];    /* input entropy                */
	uint8_t pstr[TRNG_PERS_STR_LEN];      /* personalization string       */
	uint8_t pad_data[DF_PAD_DATA_LEN];  /* pad to multiples of 16 bytes*/
};

struct versal_trng {
	struct trng_cfg cfg;
	struct trng_usr_cfg usr_cfg;
	struct trng_stats stats;
	enum trng_status status;
	uint32_t buf[RAND_BUF_LEN];   /* buffer of random bits      */
	size_t len;
	struct trng_dfin dfin;
	uint8_t dfout[TRNG_SEED_LEN]; /* output of the DF operation */
};

extern const uint8_t trng_pers_str[TRNG_PERS_STR_LEN];

TEE_Result versal_trng_hw_init(struct versal_trng *trng,
			       struct trng_usr_cfg *usr_cfg);
TEE_Result versal_trng_get_random_bytes(struct versal_trng *trng,
					void *buf, size_t len);
#endif

#endif
