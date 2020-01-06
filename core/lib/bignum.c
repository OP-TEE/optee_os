// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2018-2019 NXP
 *
 * @file    bignum.c
 *
 */
/* Global includes */
#include <crypto/crypto.h>
#include <mpalib.h>
#include <trace.h>

/**
 * @brief   Allocate a big number of \a size_bits bits size
 *
 * @param[in]  size_bits  Number of bits to allocate
 *
 * @retval  reference to the new big number allocated
 * @retval  NULL in case of allocation failure
 */
struct bignum *crypto_bignum_allocate(size_t size_bits)
{
	size_t sz = mpa_StaticVarSizeInU32(size_bits) *	sizeof(uint32_t);
	struct mpa_numbase_struct *bn = calloc(1, sz);

	if (!bn) {
		LIB_TRACE("Allocation error");
		return NULL;
	}

	bn->alloc = sz - (MPA_NUMBASE_METADATA_SIZE_IN_U32 * sizeof(uint32_t));
	/* alloc fields counts the number of BYTES_PER_WORD allocated */
	bn->alloc = bn->alloc / BYTES_PER_WORD;
	return (struct bignum *)bn;
}

/**
 * @brief   Free an allocated bignumber
 *
 * @param[in]  bn    bignumber
 *
 */
void crypto_bignum_free(struct bignum *bn)
{
	free(bn);
}

/**
 * @brief   Converts an string of bytes into a bignumber
 *
 * @param[in]  src  String of bytes
 * @param[in]  len  Length of the string
 * @param[out] dst  Bignumber resulting
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 */
TEE_Result crypto_bignum_bin2bn(const uint8_t *src, size_t len,
				struct bignum *dst)
{
	int ret;

	/* Check the parameters */
	if ((!src) || (!dst)) {
		LIB_TRACE("Bad Parameter src=@0x%"PRIxPTR" dst=@0x%"PRIxPTR"",
				(uintptr_t)src, (uintptr_t)dst);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* Call MPA library to convert the string */
	ret = mpa_set_oct_str((mpanum)dst, src, len, 0);

	if (ret == (-1)) {
		LIB_TRACE("Not enough space");
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	return TEE_SUCCESS;
}

/**
 * @brief   Get the size in bytes of the input bignumber
 *
 * @param[in]  bn    bignumber
 *
 * @retval size in bytes of the bignumber
 */
size_t crypto_bignum_num_bytes(struct bignum *bn)
{
	size_t nbBits;

	nbBits = crypto_bignum_num_bits(bn);

	return ((nbBits >> 3) + ((nbBits & 7) ? 1 : 0));
}

/**
 * @brief   Get the size in bits of the input bignumber
 *
 * @param[in]  bn    bignumber
 *
 * @retval size in bits of the bignumber
 */
size_t crypto_bignum_num_bits(struct bignum *bn)
{
	int index;

	if (!bn)
		return 0;

	/* Get the bit number of the highest 1b starting at index 0 */
	index = mpa_highest_bit_index((const mpanum)bn);

	if (index == (-1)) {
		/* mpa_highest_bit_index returns (-1) if bignumber size if 0 */
		return 0;
	}

	/* Add 1 because mpa_highest_bit_index starts at index 0 */
	index += 1;

	return index;
}

/**
 * @brief   Converts a bignumber to a string of bytes
 *
 * @param[in]  src  Bignumber
 * @param[out] dst  String resulting
 *
 */
void crypto_bignum_bn2bin(const struct bignum *src, uint8_t *dst)
{
	int    ret __maybe_unused;
	size_t len;

	/* Check the parameters */
	if ((!src) || (!dst)) {
		LIB_TRACE("Bad Parameter src=@0x%"PRIxPTR" dst=@0x%"PRIxPTR"",
				(uintptr_t)src, (uintptr_t)dst);
		return;
	}

	len = crypto_bignum_num_bytes((struct bignum *)src);
	if (len != 0) {
		ret = mpa_get_oct_str(dst, &len, (const mpanum)src);
#ifdef LIB_DEBUG
		if (ret == (-1))
			LIB_TRACE("Not enough space");
#endif
	}
}

/**
 * @brief   Bignumber copy
 *
 * @param[in]  src    bignumber source
 * @param[out] dst    bignumber destination
 *
 */
void crypto_bignum_copy(struct bignum *dst, const struct bignum *src)
{
	/* Check the parameters */
	if ((!src) || (!dst)) {
		LIB_TRACE("Bad Parameter src=@0x%"PRIxPTR" dst=@0x%"PRIxPTR"",
				(uintptr_t)src, (uintptr_t)dst);
		return;
	}

	mpa_copy((mpanum)dst, (const mpanum)src);
}

/**
 * @brief   Bignumber binary copy
 *
 * @param[in]  src    bignumber source
 * @param[out] dst    bignumber destination
 *
 */
void crypto_bignum_bin_copy(struct bignum *dst, uint8_t *src, size_t len)
{
	mpanum mpa_dst = (mpanum)dst;

	/* Check the parameters */
	if ((!src) || (!dst)) {
		LIB_TRACE("Bad Parameter src=@0x%"PRIxPTR" dst=@0x%"PRIxPTR"",
				(uintptr_t)src, (uintptr_t)dst);
		return;
	}

	mpa_dst->size = len;
	memcpy(mpa_dst->d, src, len);
}


/**
 * @brief   Fills bignumber with 0
 *
 * @param[in]  bn    bignumber
 *
 */
void crypto_bignum_clear(struct bignum *bn)
{
	mpanum mpa_bn = (mpanum)bn;
	size_t sz;

	if (!bn) {
		LIB_TRACE("Parameter is NULL");
		return;
	}

	sz = mpa_bn->alloc * BYTES_PER_WORD;
	memset(mpa_bn->d, 0, sz);
}

/**
 * @brief   Compare two bignumbers.
 *
 * @param[in]  bn_a  Bignumber A
 * @param[in]  bn_b  Bignumber B
 *
 * @retval 0     bn_a == bn_b
 * @retval (-1)  bn_a < bn_b
 * @retval (+1)  bn_a > bn_b
 */
/* return -1 if a<b, 0 if a==b, +1 if a>b */
int32_t crypto_bignum_compare(struct bignum *bn_a, struct bignum *bn_b)
{
	int32_t ret;

	/* Check the parameters */
	if ((!bn_a) || (!bn_b)) {
		LIB_TRACE("Bad Parameter bn_a=@0x%"PRIxPTR" bn_b=@0x%"PRIxPTR"",
				(uintptr_t)bn_a, (uintptr_t)bn_b);
		return (-1);
	}

	ret = mpa_cmp((const mpanum)bn_a, (const mpanum)bn_b);

	if (ret < 0)
		ret = (-1);
	else if (ret > 0)
		ret = (1);


	return ret;
}
