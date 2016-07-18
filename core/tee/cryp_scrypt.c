/*-
 * Copyright (c) 2016, Linaro Limited
 * Copyright 2009 Colin Percival
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file was originally written by Colin Percival as part of the Tarsnap
 * online backup system.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <tee/cryp_scrypt.h>
#include <tee/tee_cryp_pbkdf2.h>
#include <types_ext.h>
#include <utee_defines.h>
#include <kernel/panic.h>
#include <mpalib.h>
#include <tomcrypt_mpa.h>
#include <trace.h>
#include <util.h>

static void blkxor(void *, const void *, size_t);
static void salsa20_8(uint32_t[16]);
static void blockmix_salsa8(const uint32_t *, uint32_t *, uint32_t *, size_t);
static uint64_t integerify(const void *, size_t);

static void
blkcpy(void *dest, const void *src, size_t len)
{
	size_t *D = dest;
	const size_t *S = src;
	size_t L = len / sizeof(size_t);
	size_t i;

	for (i = 0; i < L; i++)
		D[i] = S[i];
}

static void
blkxor(void *dest, const void *src, size_t len)
{
	size_t *D = dest;
	const size_t *S = src;
	size_t L = len / sizeof(size_t);
	size_t i;

	for (i = 0; i < L; i++)
		D[i] ^= S[i];
}

/**
 * salsa20_8(B):
 * Apply the salsa20/8 core to the provided block.
 */
static void
salsa20_8(uint32_t B[16])
{
	uint32_t x[16];
	size_t i;

	blkcpy(x, B, 64);
	for (i = 0; i < 8; i += 2) {
#define R(a, b) (((a) << (b)) | ((a) >> (32 - (b))))
		/* Operate on columns. */
		x[4] ^= R(x[0]+x[12], 7);
		x[8] ^= R(x[4]+x[0], 9);
		x[12] ^= R(x[8]+x[4], 13);
		x[0] ^= R(x[12]+x[8], 18);

		x[9] ^= R(x[5]+x[1], 7);
		x[13] ^= R(x[9]+x[5], 9);
		x[1] ^= R(x[13]+x[9], 13);
		x[5] ^= R(x[1]+x[13], 18);

		x[14] ^= R(x[10]+x[6], 7);
		x[2] ^= R(x[14]+x[10], 9);
		x[6] ^= R(x[2]+x[14], 13);
		x[10] ^= R(x[6]+x[2], 18);

		x[3] ^= R(x[15]+x[11], 7);
		x[7] ^= R(x[3]+x[15], 9);
		x[11] ^= R(x[7]+x[3], 13);
		x[15] ^= R(x[11]+x[7], 18);

		/* Operate on rows. */
		x[1] ^= R(x[0]+x[3], 7);
		x[2] ^= R(x[1]+x[0], 9);
		x[3] ^= R(x[2]+x[1], 13);
		x[0] ^= R(x[3]+x[2], 18);

		x[6] ^= R(x[5]+x[4], 7);
		x[7] ^= R(x[6]+x[5], 9);
		x[4] ^= R(x[7]+x[6], 13);
		x[5] ^= R(x[4]+x[7], 18);

		x[11] ^= R(x[10]+x[9], 7);
		x[8] ^= R(x[11]+x[10], 9);
		x[9] ^= R(x[8]+x[11], 13);
		x[10] ^= R(x[9]+x[8], 18);

		x[12] ^= R(x[15]+x[14], 7);
		x[13] ^= R(x[12]+x[15], 9);
		x[14] ^= R(x[13]+x[12], 13);
		x[15] ^= R(x[14]+x[13], 18);
#undef R
	}
	for (i = 0; i < 16; i++)
		B[i] += x[i];
}

/**
 * blockmix_salsa8(Bin, Bout, X, r):
 * Compute Bout = BlockMix_{salsa20/8, r}(Bin).  The input Bin must be 128r
 * bytes in length; the output Bout must also be the same size.  The
 * temporary space X must be 64 bytes.
 */
static void
blockmix_salsa8(const uint32_t *Bin, uint32_t *Bout, uint32_t *X, size_t r)
{
	size_t i;

	/* 1: X <-- B_{2r - 1} */
	blkcpy(X, &Bin[(2 * r - 1) * 16], 64);

	/* 2: for i = 0 to 2r - 1 do */
	for (i = 0; i < 2 * r; i += 2) {
		/* 3: X <-- H(X \xor B_i) */
		blkxor(X, &Bin[i * 16], 64);
		salsa20_8(X);

		/* 4: Y_i <-- X */
		/* 6: B' <-- (Y_0, Y_2 ... Y_{2r-2}, Y_1, Y_3 ... Y_{2r-1}) */
		blkcpy(&Bout[i * 8], X, 64);

		/* 3: X <-- H(X \xor B_i) */
		blkxor(X, &Bin[i * 16 + 16], 64);
		salsa20_8(X);

		/* 4: Y_i <-- X */
		/* 6: B' <-- (Y_0, Y_2 ... Y_{2r-2}, Y_1, Y_3 ... Y_{2r-1}) */
		blkcpy(&Bout[i * 8 + r * 16], X, 64);
	}
}

/**
 * integerify(B, r):
 * Return the result of parsing B_{2r-1} as a little-endian integer.
 */
static uint64_t
integerify(const void *B, size_t r)
{
	const uint32_t *X = (const void *)((uintptr_t)(B) + (2 * r - 1) * 64);

	return (((uint64_t)(X[1]) << 32) + X[0]);
}

static inline uint32_t
le32dec(const void *pp)
{
	const uint8_t *p = (uint8_t const *)pp;

	return ((uint32_t)(p[0]) + ((uint32_t)(p[1]) << 8) +
		((uint32_t)(p[2]) << 16) + ((uint32_t)(p[3]) << 24));
}

static inline void
le32enc(void *pp, uint32_t x)
{
	uint8_t *p = (uint8_t *)pp;

	p[0] = x & 0xff;
	p[1] = (x >> 8) & 0xff;
	p[2] = (x >> 16) & 0xff;
	p[3] = (x >> 24) & 0xff;
}



/**
 * crypto_scrypt_smix(B, r, N, V, XY):
 * Compute B = SMix_r(B, N).  The input B must be 128r bytes in length;
 * the temporary storage V must be 128rN bytes in length; the temporary
 * storage XY must be 256r + 64 bytes in length.  The value N must be a
 * power of 2 greater than 1.  The arrays B, V, and XY must be aligned to a
 * multiple of 64 bytes.
 */
static void
crypto_scrypt_smix(uint8_t *B, size_t r, uint64_t N, void *_V, void *XY)
{
	uint32_t *X = XY;
	uint32_t *Y = (void *)((uint8_t *)(XY) + 128 * r);
	uint32_t *Z = (void *)((uint8_t *)(XY) + 256 * r);
	uint32_t *V = _V;
	uint64_t i;
	uint64_t j;
	size_t k;

	/* 1: X <-- B */
	for (k = 0; k < 32 * r; k++)
		X[k] = le32dec(&B[4 * k]);

	/* 2: for i = 0 to N - 1 do */
	for (i = 0; i < N; i += 2) {
		/* 3: V_i <-- X */
		blkcpy(&V[i * (32 * r)], X, 128 * r);

		/* 4: X <-- H(X) */
		blockmix_salsa8(X, Y, Z, r);

		/* 3: V_i <-- X */
		blkcpy(&V[(i + 1) * (32 * r)], Y, 128 * r);

		/* 4: X <-- H(X) */
		blockmix_salsa8(Y, X, Z, r);
	}

	/* 6: for i = 0 to N - 1 do */
	for (i = 0; i < N; i += 2) {
		/* 7: j <-- Integerify(X) mod N */
		j = integerify(X, r) & (N - 1);

		/* 8: X <-- H(X \xor V_j) */
		blkxor(X, &V[j * (32 * r)], 128 * r);
		blockmix_salsa8(X, Y, Z, r);

		/* 7: j <-- Integerify(X) mod N */
		j = integerify(Y, r) & (N - 1);

		/* 8: X <-- H(X \xor V_j) */
		blkxor(Y, &V[j * (32 * r)], 128 * r);
		blockmix_salsa8(Y, X, Z, r);
	}

	/* 10: B' <-- X */
	for (k = 0; k < 32 * r; k++)
		le32enc(&B[4 * k], X[k]);
}

struct scrypt_temp_vars {
	mpanum tmp_b;
	mpanum tmp_v;
	mpanum tmp_xy;
	uint8_t *b;
	uint32_t *v;
	uint32_t *xy;
};

static void *alloc_temp_var(size_t sz_bytes, mpanum *mpa)
{
	const size_t align = 64;
	vaddr_t va;

	if (!mpa_alloc_static_temp_var_size((sz_bytes + align) * 8, mpa,
					    external_mem_pool))
		return NULL;
	va = (vaddr_t)(*mpa)->d;
	va += align;
	va &= ~(align - 1);
	return (void *)va;
}

static void free_temp_vars(struct scrypt_temp_vars *vars)
{
	mpa_free_static_temp_var(&vars->tmp_b, external_mem_pool);
	mpa_free_static_temp_var(&vars->tmp_xy, external_mem_pool);
	mpa_free_static_temp_var(&vars->tmp_v, external_mem_pool);
	memset(vars, 0, sizeof(*vars));
}

static TEE_Result alloc_temp_vars(size_t n, size_t r, size_t p,
				  struct scrypt_temp_vars *vars)
{
	vars->tmp_b = NULL;
	vars->tmp_xy = NULL;
	vars->tmp_v = NULL;
	vars->b = alloc_temp_var(128 * r * p, &vars->tmp_b);
	vars->xy = alloc_temp_var(256 * r + 64, &vars->tmp_xy);
	vars->v = alloc_temp_var(128 * r * n, &vars->tmp_v);

	if (!vars->b || !vars->xy || !vars->v) {
		free_temp_vars(vars);
		return TEE_ERROR_OUT_OF_MEMORY;
	}
	return TEE_SUCCESS;
}

static TEE_Result validate_param(size_t n, size_t r, size_t p)
{
	const size_t rp_prod_max = BIT(30);

	if (r >= rp_prod_max || p >= rp_prod_max ||
	    (uint64_t)r * (uint64_t)p >= rp_prod_max)
		return TEE_ERROR_GENERIC;
	if (((n & (n - 1)) != 0) || (n < 2))
		return TEE_ERROR_BAD_PARAMETERS;
	if ((r > SIZE_MAX / 128 / p) ||
#if SIZE_MAX / 256 <= UINT32_MAX
	    (r > (SIZE_MAX - 64) / 256) ||
#endif
	    (n > SIZE_MAX / 128 / r))
		return TEE_ERROR_OUT_OF_MEMORY;

	return TEE_SUCCESS;
}

TEE_Result tee_scrypt_validate_param(size_t n, size_t r, size_t p)
{
	TEE_Result res = validate_param(n, r, p);
	struct scrypt_temp_vars vars;

	if (res != TEE_SUCCESS)
		return res;
	res = alloc_temp_vars(n, r, p, &vars);
	free_temp_vars(&vars);
	return res;
}

/**
 * _crypto_scrypt(passwd, passwdlen, salt, saltlen, N, r, p, buf, buflen, smix):
 * Perform the requested scrypt computation, using ${smix} as the smix routine.
 */
/**
 * crypto_scrypt(passwd, passwdlen, salt, saltlen, N, r, p, buf, buflen):
 * Compute scrypt(passwd[0 .. passwdlen - 1], salt[0 .. saltlen - 1], N, r,
 * p, buflen) and write the result into buf.  The parameters r, p, and buflen
 * must satisfy r * p < 2^30 and buflen <= (2^32 - 1) * 32.  The parameter N
 * must be a power of 2 greater than 1.
 *
 * Return 0 on success; or -1 on error.
 */

TEE_Result tee_cryp_scrypt(const uint8_t *passwd, size_t passwdlen,
			   const uint8_t *salt, size_t saltlen, uint64_t N,
			   size_t r, size_t p, uint8_t *buf,
			   size_t buflen)
{
	TEE_Result res = validate_param(N, r, p);
	struct scrypt_temp_vars vars;
	size_t i;

	if (res != TEE_SUCCESS)
		return res;

	/* Sanity-check parameters. */
#if SIZE_MAX > UINT32_MAX
	if (buflen > (((uint64_t)(1) << 32) - 1) * 32)
		return TEE_ERROR_GENERIC;
#endif

	res = alloc_temp_vars(N, r, p, &vars);
	if (res != TEE_SUCCESS)
		return res;

	/* 1: (B_0 ... B_{p-1}) <-- PBKDF2(P, S, 1, p * MFLen) */
	res = tee_cryp_pbkdf2(TEE_MAIN_ALGO_SHA256, passwd, passwdlen,
			      salt, saltlen, 1, vars.b, p * 128 * r);
	if (res != TEE_SUCCESS)
		goto out;

	/* 2: for i = 0 to p - 1 do */
	for (i = 0; i < p; i++) {
		/* 3: B_i <-- MF(B_i, N) */
		crypto_scrypt_smix(&vars.b[i * 128 * r], r, N, vars.v, vars.xy);
	}

	/* 5: DK <-- PBKDF2(P, B, 1, dkLen) */
	res = tee_cryp_pbkdf2(TEE_MAIN_ALGO_SHA256, passwd, passwdlen,
			      vars.b, p * 128 * r, 1, buf, buflen);
out:
	free_temp_vars(&vars);
	return res;
}
