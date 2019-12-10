// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2019 Huawei Technologies Co., Ltd
 */
/*
 *  mbedtlsSM2
 *
 *  Created by mac on 2018/4/18.
 *  Copyright 2018 mac. All rights reserved.
 */

#include <assert.h>
#include <mbedtls/bignum.h>
#include <mbedtls/ecp.h>
#include <sm2.h>
#include <string.h>
#include <tee_internal_api.h>
#include <util.h>

#define BN2BIN_SIZE 512
uint8_t bn2binbuffer[BN2BIN_SIZE];

static void append_bin(struct sm2_hash *h, size_t size)
{
	assert(h->position + size <= ARRAY_SIZE(bn2binbuffer));
	memcpy(h->buffer + h->position, &bn2binbuffer[BN2BIN_SIZE - size],
	       size);
	h->position += size;
}

static void append_str(struct sm2_hash *h, uint8_t *buf, size_t size)
{
	assert(h->position + size <= ARRAY_SIZE(bn2binbuffer));
	memcpy(h->buffer + h->position, buf, size);
	h->position += size;
}

static size_t byte_length(size_t bit_length)
{
	return (bit_length + 7) / 8;
}

static int hash256(uint8_t *in, size_t size, uint8_t *out)
{
	uint32_t out_size = size;
	TEE_OperationHandle op = NULL;
	TEE_Result res = TEE_ERROR_GENERIC;
	int ret = 0;

	if (size > out_size)
		return MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
	res = TEE_AllocateOperation(&op, TEE_ALG_SHA256, TEE_MODE_DIGEST, 0);
	if (res)
		return MBEDTLS_ERR_MPI_ALLOC_FAILED;
	res = TEE_DigestDoFinal(op, in, size, out, &out_size);
	if (res)
		ret = MBEDTLS_ERR_MPI_BAD_INPUT_DATA;

	TEE_FreeOperation(op);

	return ret;
}

/*
 * Generates a random number @a such that @a < @b.
 * Returns an Mbed TLS status code.
 */
static int random_num(mbedtls_mpi *a, size_t bytes, mbedtls_mpi *b)
{
	uint8_t *rnd = NULL;
	int res = 0;

	rnd = TEE_Malloc(bytes, 0);
	if (!rnd)
		return MBEDTLS_ERR_MPI_ALLOC_FAILED;
	TEE_GenerateRandom(rnd, bytes);
	res = mbedtls_mpi_read_binary(a, rnd, bytes);
	if (res)
		goto cleanup;
	while (mbedtls_mpi_cmp_mpi(a, b) >= 0) {
		res = mbedtls_mpi_shift_r(a, 1);
		if (res)
			goto cleanup;
	}
cleanup:
	TEE_Free(rnd);
	return res;
}

int sm2_sign(mbedtls_ecp_group *ecp, struct sm2_sign_ctx *ctx)
{
	int res = 0;
	size_t num_size;
	struct sm2_hash e;
	struct sm2_hash Z_A;
	mbedtls_ecp_point kG;
	mbedtls_mpi e_n, k_n, r_n, s_n, temp;

	mbedtls_mpi_init(&s_n);
	mbedtls_mpi_init(&e_n);
	mbedtls_mpi_init(&k_n);
	mbedtls_mpi_init(&r_n);
	mbedtls_mpi_init(&temp);
	mbedtls_ecp_point_init(&kG);

	/* step 1 */

	/* Z = H(ENTL || ID A || a || b || x G || y G || x A || y A) */
	memset(&Z_A, 0, sizeof(Z_A));
	Z_A.buffer[0] = ((ctx->ENTL * 8) >> 8) & 0xff;
	Z_A.buffer[1] = (ctx->ENTL * 8) & 0xff;
	Z_A.position += 2;

	append_str(&Z_A, ctx->ID, ctx->ENTL);

	res = mbedtls_mpi_write_binary(&ecp->A, bn2binbuffer, BN2BIN_SIZE);
	if (res)
		goto cleanup;
	num_size = mbedtls_mpi_size(&ecp->A);
	append_bin(&Z_A, num_size);

	res = mbedtls_mpi_write_binary(&ecp->B, bn2binbuffer, BN2BIN_SIZE);
	if (res)
		goto cleanup;
	num_size = mbedtls_mpi_size(&ecp->B);
	append_bin(&Z_A, num_size);

	res = mbedtls_mpi_write_binary(&ecp->G.X, bn2binbuffer, BN2BIN_SIZE);
	if (res)
		goto cleanup;
	num_size = mbedtls_mpi_size(&ecp->G.X);
	append_bin(&Z_A, num_size);

	res = mbedtls_mpi_write_binary(&ecp->G.Y, bn2binbuffer, BN2BIN_SIZE);
	if (res)
		goto cleanup;
	num_size = mbedtls_mpi_size(&ecp->G.Y);
	append_bin(&Z_A, num_size);

	res = mbedtls_mpi_write_binary(&ctx->key_pair->Q.X, bn2binbuffer,
				       BN2BIN_SIZE);
	if (res)
		goto cleanup;
	num_size = mbedtls_mpi_size(&ctx->key_pair->Q.X);
	append_bin(&Z_A, num_size);

	res = mbedtls_mpi_write_binary(&ctx->key_pair->Q.Y, bn2binbuffer,
				       BN2BIN_SIZE);
	if (res)
		goto cleanup;
	num_size = mbedtls_mpi_size(&ctx->key_pair->Q.Y);
	append_bin(&Z_A, num_size);

	res = hash256(Z_A.buffer, Z_A.position, Z_A.hash);
	if (res)
		goto cleanup;
	memcpy(ctx->Z, Z_A.hash, HASH_BYTE_LENGTH);

	/* step 2 */

	memset(&e, 0, sizeof(e));
	append_str(&e, ctx->Z, HASH_BYTE_LENGTH);
	append_str(&e, ctx->message, ctx->message_size);

	res = hash256(e.buffer, e.position, e.hash);
	if (res)
		goto cleanup;

	res = mbedtls_mpi_read_binary(&e_n, e.hash, HASH_BYTE_LENGTH);
	if (res)
		goto cleanup;

	/* step 3 */

	res = random_num(&k_n, byte_length(ecp->nbits), &ecp->N);
	if (res)
		goto cleanup;
	res = mbedtls_mpi_write_binary(&k_n, ctx->k, byte_length(ecp->nbits));
	if (res)
		goto cleanup;

	/* step 4 */

	res = mbedtls_ecp_mul(ecp,  &kG, &k_n, &ecp->G, NULL, NULL);
	if (res)
		goto cleanup;

	/* step 5 */

	res = mbedtls_mpi_add_mpi(&r_n, &e_n, &kG.X);
	if (res)
		goto cleanup;
	res = mbedtls_mpi_mod_mpi(&r_n, &r_n, &ecp->N);
	if (res)
		goto cleanup;

	/* step 6 */

	res = mbedtls_mpi_add_int(&temp, &ctx->key_pair->d, 1);
	if (res)
		goto cleanup;
	res = mbedtls_mpi_inv_mod(&temp, &temp, &ecp->N);
	if (res)
		goto cleanup;
	res = mbedtls_mpi_mul_mpi(&s_n, &r_n, &ctx->key_pair->d);
	if (res)
		goto cleanup;
	res = mbedtls_mpi_sub_mpi(&s_n, &k_n, &s_n);
	if (res)
		goto cleanup;

	res = mbedtls_mpi_mul_mpi(&s_n, &temp, &s_n);
	if (res)
		goto cleanup;
	res = mbedtls_mpi_mod_mpi(&s_n, &s_n, &ecp->N);
	if (res)
		goto cleanup;

	res = mbedtls_mpi_write_binary(&r_n, ctx->r, byte_length(ecp->nbits));
	if (res)
		goto cleanup;
	res = mbedtls_mpi_write_binary(&s_n, ctx->s, byte_length(ecp->nbits));
	if (res)
		goto cleanup;

cleanup:
	mbedtls_mpi_free(&e_n);
	mbedtls_mpi_free(&k_n);
	mbedtls_mpi_free(&r_n);
	mbedtls_mpi_free(&s_n);
	mbedtls_mpi_free(&temp);
	mbedtls_ecp_point_free(&kG);
	return res;
}

int sm2_verify(mbedtls_ecp_group *ecp, struct sm2_sign_ctx *ctx)
{
	int res = 0;
	struct sm2_hash e;
	mbedtls_ecp_point sGtP;
	mbedtls_mpi e_n, r_n, s_n, t_n, R_n;

	memset(&e, 0, sizeof(e));
	mbedtls_ecp_point_init(&sGtP);
	mbedtls_mpi_init(&e_n);
	mbedtls_mpi_init(&r_n);
	mbedtls_mpi_init(&s_n);
	mbedtls_mpi_init(&t_n);
	mbedtls_mpi_init(&R_n);

	/* step 3 4 */

	append_str(&e, ctx->Z, HASH_BYTE_LENGTH);
	append_str(&e, ctx->message, ctx->message_size);
	res = hash256(e.buffer, e.position, e.hash);
	if (res)
		goto cleanup;

	res = mbedtls_mpi_read_binary(&e_n, e.hash, HASH_BYTE_LENGTH);
	if (res)
		goto cleanup;

	/* step 5 */
	res = mbedtls_mpi_read_binary(&r_n, ctx->r, byte_length(ecp->nbits));
	if (res)
		goto cleanup;
	res = mbedtls_mpi_read_binary(&s_n, ctx->s, byte_length(ecp->nbits));
	if (res)
		goto cleanup;

	res = mbedtls_mpi_add_mpi(&t_n, &r_n, &s_n);
	if (res)
		goto cleanup;
	res = mbedtls_mpi_mod_mpi(&t_n, &t_n, &ecp->N);
	if (res)
		goto cleanup;

	/* step 6 */
	res = mbedtls_ecp_muladd(ecp, &sGtP, &s_n, &ecp->G, &t_n,
				 &ctx->key_pair->Q);
	if (res)
		goto cleanup;

	/* step 7 */
	res = mbedtls_mpi_add_mpi(&R_n, &e_n, &sGtP.X);
	if (res)
		goto cleanup;
	res = mbedtls_mpi_mod_mpi(&R_n, &R_n, &ecp->N);
	if (res)
		goto cleanup;
	res = mbedtls_mpi_cmp_mpi(&R_n, &r_n);
	if (res)
		goto cleanup;

cleanup:
	mbedtls_ecp_point_free(&sGtP);
	mbedtls_mpi_free(&e_n);
	mbedtls_mpi_free(&r_n);
	mbedtls_mpi_free(&s_n);
	mbedtls_mpi_free(&t_n);
	mbedtls_mpi_free(&R_n);
	return res;
}
