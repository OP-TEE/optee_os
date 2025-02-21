/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2022 Xilinx, Inc.  All rights reserved.
 * Copyright (C) 2022 Foundries Ltd.
 * Copyright (C) 2023 ProvenRun SAS.
 */

#ifndef __DRIVERS_VERSAL_TRNG_H
#define __DRIVERS_VERSAL_TRNG_H

#include <stdbool.h>
#include <stdlib.h>
#include <tee_api_types.h>
#include <types_ext.h>
#include <util.h>

#define TRNG_SEED_LEN		48
#define TRNG_V2_SEED_LEN	128
#define TRNG_PERS_STR_REGS	12
#define TRNG_PERS_STR_LEN	48
#define RAND_BUF_LEN		4

/* Derivative function helper macros */
#define DF_SEED			0
#define DF_RAND			1
#define DF_IP_IV_LEN		4
#define DF_PAD_DATA_LEN		8
#define MAX_PRE_DF_LEN		160
#define MAX_PRE_DF_LEN_WORDS	40
#define DF_PERS_STR_LEN		TRNG_PERS_STR_LEN
#define DF_PAD_VAL		0x80
#define DF_KEY_LEN		32
#define BLK_SIZE		16
#define MAX_ROUNDS		14

enum trng_version {
	TRNG_V1 = 1,
	TRNG_V2 = 2,
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
	uint8_t pstr[DF_PERS_STR_LEN];      /* personalization string       */
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

TEE_Result versal_trng_hw_init(struct versal_trng *trng,
			       struct trng_usr_cfg *usr_cfg);
TEE_Result versal_trng_get_random_bytes(struct versal_trng *trng,
					void *buf, size_t len);

#endif /* __DRIVERS_VERSAL_TRNG_H */
