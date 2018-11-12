// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */
#include <stdio.h>
#include <tee_api.h>
#include <tee_arith_internal.h>
#include <mpalib.h>
#include <mempool.h>

/*
 * The mem pool.
 * We have a pool of scratch memory for internal usage.
 * The variables in the pool are twice the size of the max allowed
 * size from the TA. This is to coop with modulare multiplication.
 */

#define MPA_INTERNAL_MEM_POOL_SIZE 12

static uint32_t mempool_u32[mpa_scratch_mem_size_in_U32(
					    MPA_INTERNAL_MEM_POOL_SIZE,
					    CFG_TA_BIGNUM_MAX_BITS)];
static mpa_scratch_mem mempool;

/*************************************************************
 * PANIC
 *************************************************************/

/*
 * TEE_BigInt_Panic
 *
 * This is a temporary solution for testing the TEE_BigInt lib
 */
static void __attribute__ ((noreturn)) TEE_BigInt_Panic(const char *msg)
{
	printf("PANIC: %s\n", msg);
	TEE_Panic(0xB16127 /*BIGINT*/);
	while (1)
		; /* Panic will crash the thread */
}

/*************************************************************
 * INITIALIZATION FUNCTIONS
 *************************************************************/

/*
 * _TEE_MathAPI_Init
 */
void _TEE_MathAPI_Init(void)
{
	static mpa_scratch_mem_base mem;

	mem.pool = mempool_alloc_pool(mempool_u32, sizeof(mempool_u32), NULL);
	if (!mem.pool)
		TEE_Panic(0);
	/*
	 * The default size (bits) of a big number that will be required is
	 * equal to the max size of the computation (for example 4096
	 * bits), multiplied by 2 to allow overflow in computation
	 */
	mem.bn_bits = CFG_TA_BIGNUM_MAX_BITS * 2;
	mempool = &mem;
}

/*
 * TEE_BigIntInit
 */
void TEE_BigIntInit(TEE_BigInt *bigInt, uint32_t len)
{
	mpa_init_static((mpa_num_base *)bigInt, (uint32_t)len);
}

/*
 * TEE_BigIntInitFMM
 */
void TEE_BigIntInitFMM(TEE_BigIntFMM *bigIntFMM, uint32_t len)
{
	mpanum op = (mpa_num_base *)bigIntFMM;

	op->alloc = U32_TO_ASIZE(len - MPA_NUMBASE_METADATA_SIZE_IN_U32);
	op->size = 0;
}

/*
 * TEE_BigIntInitFMMContext
 */
void TEE_BigIntInitFMMContext(TEE_BigIntFMMContext *context,
			      uint32_t len, const TEE_BigInt *modulus)
{
	mpa_fmm_context mpa_context = (mpa_fmm_context_base *)context;
	mpanum mpa_modulus = (mpa_num_base *)modulus;

	mpa_init_static_fmm_context(mpa_context, (uint32_t)len);
	mpa_compute_fmm_context(mpa_modulus, mpa_context->r_ptr,
				mpa_context->r2_ptr, &mpa_context->n_inv,
				mempool);
}

/*************************************************************
 * MEMORY ALLOCATION AND SIZE
 *************************************************************/

/*
 * TEE_BigIntFMMSizeInU32
 */
uint32_t TEE_BigIntFMMSizeInU32(uint32_t modulusSizeInBits)
{
	return TEE_BigIntSizeInU32(modulusSizeInBits) + 1;
}

/*
 * TEE_BigIntFMMContextSizeInU32
 */
uint32_t TEE_BigIntFMMContextSizeInU32(uint32_t modulusSizeInBits)
{
	return mpa_fmm_context_size_in_U32(modulusSizeInBits);
}

/*************************************************************
 * CONVERSION FUNCTIONS
 *************************************************************/

/*
 * TEE_BigIntConvertFromOctetString
 */
TEE_Result TEE_BigIntConvertFromOctetString(TEE_BigInt *dest,
					    const uint8_t *buffer,
					    uint32_t bufferLen,
					    int32_t sign)
{
	TEE_Result res;
	mpanum mpa_dest = (mpa_num_base *)dest;
	bool negative = sign < 0;

	if (mpa_set_oct_str(mpa_dest, buffer, bufferLen, negative) != 0)
		res = TEE_ERROR_OVERFLOW;
	else
		res = TEE_SUCCESS;

	if (res != TEE_SUCCESS &&
	    res != TEE_ERROR_OVERFLOW)
		TEE_Panic(res);

	return res;
}

/*
 * TEE_BigIntConvertToOctetString
 */
TEE_Result TEE_BigIntConvertToOctetString(uint8_t *buffer,
					  uint32_t *bufferLen,
					  const TEE_BigInt *bigInt)
{
	mpanum n = (mpa_num_base *)bigInt;
	size_t size = *bufferLen;
	TEE_Result res;

	if (mpa_get_oct_str(buffer, &size, n) != 0)
		res = TEE_ERROR_SHORT_BUFFER;
	else
		res = TEE_SUCCESS;

	*bufferLen = size;

	if (res != TEE_SUCCESS &&
	    res != TEE_ERROR_SHORT_BUFFER)
		TEE_Panic(res);

	return res;
}

/*
 * TEE_BigIntConvertFromS32
 */
void TEE_BigIntConvertFromS32(TEE_BigInt *dest, int32_t shortVal)
{
	mpanum mpa_dest = (mpa_num_base *)dest;

#if (MPA_WORD_SIZE == 32)
	mpa_set_S32(mpa_dest, shortVal);
#else
#error "Write code for digit size != 32"
#endif
}

/*
 * TEE_BigIntConvertToS32
 */
TEE_Result TEE_BigIntConvertToS32(int32_t *dest, const TEE_BigInt *src)
{
	TEE_Result res;
	mpanum mpa_src = (mpa_num_base *)src;

	if (mpa_get_S32(dest, mpa_src) == 0)
		res = TEE_SUCCESS;
	else
		res = TEE_ERROR_OVERFLOW;

	if (res != TEE_SUCCESS &&
	    res != TEE_ERROR_OVERFLOW)
		TEE_Panic(res);

	return res;
}

/*************************************************************
 * LOGICAL OPERATIONS
 *************************************************************/

/*
 * TEE_BigIntCmp
 */
int32_t TEE_BigIntCmp(const TEE_BigInt *op1, const TEE_BigInt *op2)
{
	mpanum mpa_op1 = (mpa_num_base *)op1;
	mpanum mpa_op2 = (mpa_num_base *)op2;

	return mpa_cmp(mpa_op1, mpa_op2);
}

/*
 * TEE_BigIntCmpS32
 */
int32_t TEE_BigIntCmpS32(const TEE_BigInt *op, int32_t shortVal)
{
	mpanum mpa_op = (mpa_num_base *)op;

	return mpa_cmp_short(mpa_op, shortVal);
}

/*
 * TEE_BigIntShiftRight
 */
void TEE_BigIntShiftRight(TEE_BigInt *dest, const TEE_BigInt *op,
			  size_t bits)
{
	mpanum mpa_dest = (mpa_num_base *)dest;
	mpanum mpa_op = (mpa_num_base *)op;

	mpa_shift_right(mpa_dest, mpa_op, (mpa_asize_t) bits);
}

/*
 * TEE_BigIntGetBit
 */
bool TEE_BigIntGetBit(const TEE_BigInt *src, uint32_t bitIndex)
{
	mpanum mpa_src = (mpa_num_base *)src;

	return mpa_get_bit(mpa_src, bitIndex);
}

/*
 * TEE_BigIntGetBitCount
 */
uint32_t TEE_BigIntGetBitCount(const TEE_BigInt *src)
{
	mpanum mpa_src = (mpa_num_base *)src;

	return mpa_highest_bit_index(mpa_src) + 1;
}

/*************************************************************
 * BASIC ARITHMETIC OPERATIONS
 *************************************************************/

/*
 * TEE_BigIntAdd
 */
void TEE_BigIntAdd(TEE_BigInt *dest, const TEE_BigInt *op1,
		   const TEE_BigInt *op2)
{
	mpanum mpa_dest = (mpa_num_base *)dest;
	mpanum mpa_op1 = (mpa_num_base *)op1;
	mpanum mpa_op2 = (mpa_num_base *)op2;

	mpa_add(mpa_dest, mpa_op1, mpa_op2, mempool);
}

/*
 * TEE_BigIntSub
 */
void TEE_BigIntSub(TEE_BigInt *dest, const TEE_BigInt *op1,
		   const TEE_BigInt *op2)
{
	mpanum mpa_dest = (mpa_num_base *)dest;
	mpanum mpa_op1 = (mpa_num_base *)op1;
	mpanum mpa_op2 = (mpa_num_base *)op2;

	mpa_sub(mpa_dest, mpa_op1, mpa_op2, mempool);
}

/*
 * TEE_BigIntNeg
 */
void TEE_BigIntNeg(TEE_BigInt *dest, const TEE_BigInt *src)
{
	mpanum mpa_dest = (mpa_num_base *)dest;
	mpanum mpa_src = (mpa_num_base *)src;

	mpa_neg(mpa_dest, mpa_src);
}

/*
 * TEE_BigIntMul
 */
void TEE_BigIntMul(TEE_BigInt *dest, const TEE_BigInt *op1,
		   const TEE_BigInt *op2)
{
	mpanum mpa_dest = (mpa_num_base *)dest;
	mpanum mpa_op1 = (mpa_num_base *)op1;
	mpanum mpa_op2 = (mpa_num_base *)op2;

	mpa_mul(mpa_dest, mpa_op1, mpa_op2, mempool);
}

/*
 * TEE_BigIntSquare
 */
void TEE_BigIntSquare(TEE_BigInt *dest, const TEE_BigInt *op)
{
	mpanum mpa_dest = (mpa_num_base *)dest;
	mpanum mpa_op = (mpa_num_base *)op;

	mpa_mul(mpa_dest, mpa_op, mpa_op, mempool);
}

/*
 * TEE_BigIntDiv
 */
void TEE_BigIntDiv(TEE_BigInt *dest_q, TEE_BigInt *dest_r,
		   const TEE_BigInt *op1, const TEE_BigInt *op2)
{
	mpanum mpa_dest_q = (mpa_num_base *)dest_q;
	mpanum mpa_dest_r = (mpa_num_base *)dest_r;
	mpanum mpa_op1 = (mpa_num_base *)op1;
	mpanum mpa_op2 = (mpa_num_base *)op2;

	if (TEE_BigIntCmpS32(op2, 0) == 0)
		TEE_BigInt_Panic("Divisor is zero");

	mpa_div(mpa_dest_q, mpa_dest_r, mpa_op1, mpa_op2, mempool);
}

/*************************************************************
 * MODULUS OPERATIONS
 *************************************************************/

/*
 * TEE_BigIntMod
 */
void TEE_BigIntMod(TEE_BigInt *dest, const TEE_BigInt *op,
		   const TEE_BigInt *n)
{
	mpanum mpa_dest = (mpa_num_base *)dest;
	mpanum mpa_op = (mpa_num_base *)op;
	mpanum mpa_n = (mpa_num_base *)n;

	if (TEE_BigIntCmpS32(n, 2) < 0)
		TEE_BigInt_Panic("Modulus is too short");

	mpa_mod(mpa_dest, mpa_op, mpa_n, mempool);

	if (mpa_cmp_short(mpa_dest, 0) < 0)
		mpa_add(mpa_dest, mpa_dest, mpa_n, mempool);
}

/*
 * TEE_BigIntAddMod
 */
void TEE_BigIntAddMod(TEE_BigInt *dest, const TEE_BigInt *op1,
		      const TEE_BigInt *op2, const TEE_BigInt *n)
{
	mpanum mpa_dest = (mpa_num_base *)dest;
	mpanum mpa_op1 = (mpa_num_base *)op1;
	mpanum mpa_op2 = (mpa_num_base *)op2;
	mpanum mpa_n = (mpa_num_base *)n;

	if (TEE_BigIntCmpS32(n, 2) < 0)
		TEE_BigInt_Panic("Modulus is too short");

	mpa_add_mod(mpa_dest, mpa_op1, mpa_op2, mpa_n, mempool);
	if (mpa_cmp_short(mpa_dest, 0) < 0)
		mpa_add(mpa_dest, mpa_dest, mpa_n, mempool);
}

/*
 * TEE_BigIntSubMod
 */
void TEE_BigIntSubMod(TEE_BigInt *dest, const TEE_BigInt *op1,
		      const TEE_BigInt *op2, const TEE_BigInt *n)
{
	mpanum mpa_dest = (mpa_num_base *)dest;
	mpanum mpa_op1 = (mpa_num_base *)op1;
	mpanum mpa_op2 = (mpa_num_base *)op2;
	mpanum mpa_n = (mpa_num_base *)n;

	if (TEE_BigIntCmpS32(n, 2) < 0)
		TEE_BigInt_Panic("Modulus is too short");

	mpa_sub_mod(mpa_dest, mpa_op1, mpa_op2, mpa_n, mempool);
	if (mpa_cmp_short(mpa_dest, 0) < 0)
		mpa_add(mpa_dest, mpa_dest, mpa_n, mempool);
}

/*
 *  TEE_BigIntMulMod
 */
void TEE_BigIntMulMod(TEE_BigInt *dest, const TEE_BigInt *op1,
		      const TEE_BigInt *op2, const TEE_BigInt *n)
{
	mpanum mpa_dest = (mpa_num_base *)dest;
	mpanum mpa_op1 = (mpa_num_base *)op1;
	mpanum mpa_op2 = (mpa_num_base *)op2;
	mpanum mpa_n = (mpa_num_base *)n;
	mpanum tmp_dest;

	if (TEE_BigIntCmpS32(n, 2) < 0)
		TEE_BigInt_Panic("Modulus is too short");

	/*
	 * From the spec, mpa_dest must be of magnitude "mpa_n"
	 * But internal computations in mpa do not have such assumptions
	 * (as __mpa_div_q_r, where "r" must be of magnitude "op1",
	 * whereas GP provides a magnitude of "op2")
	 * This is a tempory variable is used, before storing the
	 * final result.
	 */
	mpa_alloc_static_temp_var(&tmp_dest, mempool);
	mpa_mul_mod(tmp_dest, mpa_op1, mpa_op2, mpa_n, mempool);
	if (mpa_cmp_short(tmp_dest, 0) < 0)
		mpa_add(tmp_dest, tmp_dest, mpa_n, mempool);
	mpa_copy(mpa_dest, tmp_dest);
	mpa_free_static_temp_var(&tmp_dest, mempool);
}

/*
 * TEE_BigIntSquareMod
 */
void TEE_BigIntSquareMod(TEE_BigInt *dest, const TEE_BigInt *op,
			 const TEE_BigInt *n)
{
	TEE_BigIntMulMod(dest, op, op, n);
}

/*
 * TEE_BigIntInvMod
 */
void TEE_BigIntInvMod(TEE_BigInt *dest, const TEE_BigInt *op,
		      const TEE_BigInt *n)
{
	mpanum mpa_dest = (mpa_num_base *)dest;
	mpanum mpa_op = (mpa_num_base *)op;
	mpanum mpa_n = (mpa_num_base *)n;

	if (TEE_BigIntCmpS32(n, 2) < 0 || TEE_BigIntCmpS32(op, 0) == 0)
		TEE_BigInt_Panic("too small modulus or trying to invert zero");

	mpa_inv_mod(mpa_dest, mpa_op, mpa_n, mempool);
}

/*************************************************************
 * OTHER ARITHMETIC OPERATIONS
 *************************************************************/

/*
 * TEE_BigIntRelativePrime
 */
bool TEE_BigIntRelativePrime(const TEE_BigInt *op1, const TEE_BigInt *op2)
{
	mpanum mpa_op1 = (mpa_num_base *)op1;
	mpanum mpa_op2 = (mpa_num_base *)op2;
	mpanum gcd;
	uint32_t cmp;

	mpa_alloc_static_temp_var(&gcd, mempool);

	mpa_gcd(gcd, mpa_op1, mpa_op2, mempool);
	cmp = mpa_cmp_short(gcd, 1);

	mpa_free_static_temp_var(&gcd, mempool);

	return cmp == 0 ? true : false;
}

/*
 * TEE_BigIntExtendedGcd
 */
void TEE_BigIntComputeExtendedGcd(TEE_BigInt *gcd, TEE_BigInt *u,
				  TEE_BigInt *v, const TEE_BigInt *op1,
				  const TEE_BigInt *op2)
{
	mpanum mpa_gcd_res = (mpa_num_base *)gcd;
	mpanum mpa_u = (mpa_num_base *)u;
	mpanum mpa_v = (mpa_num_base *)v;
	mpanum mpa_op1 = (mpa_num_base *)op1;
	mpanum mpa_op2 = (mpa_num_base *)op2;

	mpa_extended_gcd(mpa_gcd_res, mpa_u, mpa_v, mpa_op1, mpa_op2, mempool);
}

/*
 *  TEE_BigIntIsProbablePrime
 */
int32_t TEE_BigIntIsProbablePrime(const TEE_BigInt *op,
				  uint32_t confidenceLevel)
{
	mpanum mpa_op = (mpa_num_base *)op;

	if (confidenceLevel < 80)
		confidenceLevel = 80;

	if (confidenceLevel > 256)
		confidenceLevel = 256;

	return mpa_is_prob_prime(mpa_op, confidenceLevel, mempool);
}

/*************************************************************
 * FAST MODULAR MULTIPLICATION
 *************************************************************/

/*
 * TEE_BigIntConvertToFMM
 */
void TEE_BigIntConvertToFMM(TEE_BigIntFMM *dest,
			    const TEE_BigInt *src,
			    const TEE_BigInt *n,
			    const TEE_BigIntFMMContext *context)
{
	mpanum mpa_dest = (mpa_num_base *)dest;
	mpanum mpa_op1 = (mpa_num_base *)src;
	mpanum mpa_n = (mpa_num_base *)n;
	mpa_fmm_context mpa_context = (mpa_fmm_context_base *)context;

	/* calculate dest = Mont(src, r2) */
	mpa_montgomery_mul(mpa_dest, mpa_op1, mpa_context->r2_ptr, mpa_n,
			   mpa_context->n_inv, mempool);
}

/*
 * TEE_BigIntConvertFromFMM
 */
void TEE_BigIntConvertFromFMM(TEE_BigInt *dest,
			      const TEE_BigIntFMM *src,
			      const TEE_BigInt *n,
			      const TEE_BigIntFMMContext *context)
{
	mpanum mpa_dest = (mpa_num_base *)dest;
	mpanum mpa_op2 = (mpa_num_base *)src;
	mpanum mpa_n = (mpa_num_base *)n;
	mpa_fmm_context mpa_context = (mpa_fmm_context_base *)context;
	mpanum temp_dest;

	/*
	 * Since dest in BigIntFFMCompute (i.e. dest in mpa_montgomery_mul)
	 * must have alloc one word more than the size of n, we must
	 * use a temp variable during the conversion.
	 */
	mpa_alloc_static_temp_var(&temp_dest, mempool);

	/* calculate dest = Mont(1,src) */
	mpa_montgomery_mul(temp_dest, mpa_constant_one(), mpa_op2, mpa_n,
			   mpa_context->n_inv, mempool);

	mpa_copy(mpa_dest, temp_dest);
	mpa_free_static_temp_var(&temp_dest, mempool);
}

/*
 *  TEE_BigIntComputeFMM
 */
void TEE_BigIntComputeFMM(TEE_BigIntFMM *dest,
			  const TEE_BigIntFMM *op1,
			  const TEE_BigIntFMM *op2,
			  const TEE_BigInt *n,
			  const TEE_BigIntFMMContext *context)
{
	mpanum mpa_dest = (mpa_num_base *)dest;
	mpanum mpa_op1 = (mpa_num_base *)op1;
	mpanum mpa_op2 = (mpa_num_base *)op2;
	mpanum mpa_n = (mpa_num_base *)n;
	mpa_fmm_context mpa_context = (mpa_fmm_context_base *)context;

	mpa_montgomery_mul(mpa_dest, mpa_op1, mpa_op2, mpa_n,
			   mpa_context->n_inv, mempool);
}
