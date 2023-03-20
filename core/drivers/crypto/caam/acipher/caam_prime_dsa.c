// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2020-2021, 2023 NXP
 *
 * CAAM DSA Prime Numbering.
 * Implementation of Prime Number functions
 */
#include <caam_common.h>
#include <caam_desc_ccb_defines.h>
#include <caam_jr.h>
#include <caam_utils_mem.h>
#include <crypto/crypto.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <string.h>
#include <tee_api_types.h>
#include <tee/cache.h>

#include "local.h"

#define PRIME_DESC_ENTRIES 62

/* Define the number max of try to generate valid primes */
#define DSA_MAX_TRIES_PRIME_Q 50000
#define DSA_MAX_TRIES_PRIME_P 500

#define DSA_TRY_FAIL	    0x42
#define DSA_NOT_PRIME	    0x43
#define DSA_PRIME_TOO_SMALL 0x44

struct dsa_hash {
	unsigned int op; /* CAAM Hash operation code */
	size_t size;	 /* Hash digest size */
};

/*
 * Build the descriptor generating a DSA prime Q
 * Referring to FIPS.186-4, Section A.1.1.2 Generation of the
 * Probable Primes p and q Using an Approved Hash Function
 *
 * @desc          [out] Descriptor built
 * @seed          [out] Resulting seed used to generate prime
 * @prime         [in/out] Prime generation data
 * @hash_func     Selected Hash function
 */
static void do_desc_prime_q(uint32_t *desc, struct caambuf *seed,
			    struct prime_data_dsa *prime,
			    struct dsa_hash *hash_func)
{
	unsigned int desclen = 0;
	unsigned int retry_new_mr_failed = 0;
	unsigned int retry_mr_test = 0;

	caam_desc_init(desc);
	caam_desc_add_word(desc, DESC_HEADER(0));

	/* Set the PKHA N and A register size */
	caam_desc_add_word(desc, LD_IMM(CLASS_1, REG_PKHA_N_SIZE, 4));
	caam_desc_add_word(desc, prime->q->length);
	caam_desc_add_word(desc, LD_IMM(CLASS_1, REG_PKHA_A_SIZE, 4));
	caam_desc_add_word(desc, prime->q->length);

	caam_desc_add_word(desc, MATH(ADD, ZERO, IMM_DATA, VSOL, 4));
	caam_desc_add_word(desc, DSA_MAX_TRIES_PRIME_Q);

	caam_desc_add_word(desc, MATHI_OP1(SHIFT_L, ONE, 63, REG2, 8));

	retry_new_mr_failed = caam_desc_get_len(desc);

	/* Decrement the number of try */
	caam_desc_add_word(desc, MATH(SUB, VSOL, ONE, VSOL, 4));
	/* Exceed retry count - exit with DSA_TRY_FAIL error */
	caam_desc_add_word(desc,
			   HALT_USER(ALL_COND_TRUE, MATH_N, DSA_TRY_FAIL));

	/* Clear Class 2 SHA */
	caam_desc_add_word(desc, LD_IMM(CLASS_NO, REG_CLEAR_WRITTEN, 4));
	caam_desc_add_word(desc, CLR_WR_RST_C2_CHA | CLR_WR_RST_C2_DSZ);

	/*
	 * Step 5. Generate Random Seed
	 *
	 * Seed Length shall be equal or greater than N (Q prime length)
	 * Seed result push in Message Data
	 */
	if (seed->length > 16) {
		caam_desc_add_word(desc, LD_IMM(CLASS_NO, REG_NFIFO_n_SIZE, 4));
		caam_desc_add_word(desc, NFIFO_PAD(BOTH, 0, MSG, RND, 16));

		caam_desc_add_word(desc, LD_IMM(CLASS_NO, REG_NFIFO_n_SIZE, 4));
		caam_desc_add_word(desc,
				   NFIFO_PAD(BOTH, NFIFO_LC1 | NFIFO_LC2, MSG,
					     RND, seed->length - 16));
	} else {
		caam_desc_add_word(desc, LD_IMM(CLASS_NO, REG_NFIFO_n_SIZE, 4));
		caam_desc_add_word(desc, NFIFO_PAD(BOTH, NFIFO_LC1 | NFIFO_LC2,
						   MSG, RND, seed->length));
	}

	caam_desc_add_word(desc, MOVE(C1_ALIGN, OFIFO, 0, seed->length));
	caam_desc_add_word(desc, FIFO_ST(CLASS_NO, MSG_DATA, seed->length));
	caam_desc_add_ptr(desc, seed->paddr);

	/*
	 * Hash the Seed, this is a pseudo U, bits upper N - 1 still present
	 */
	caam_desc_add_word(desc, HASH_INITFINAL(hash_func->op));

	/*
	 * Step 6. U = hash(seed) mod 2^(N-1)
	 * Step 7. q = 2^(N-1) + U + 1 - (U mod 2)
	 */
	/* Trash the bits > N - 1, the hash size is >= N */
	caam_desc_add_word(desc,
			   MOVE_WAIT(C2_CTX_REG, MATH_REG0,
				     hash_func->size - prime->q->length, 8));

	/* Get the MSB of U and set the bit N-1 */
	caam_desc_add_word(desc, MATH(OR, REG2, REG0, REG0, 8));

	/* Move the candidate prime q's MSB into IFIFO */
	caam_desc_add_word(desc, MOVE_WAIT(MATH_REG0, IFIFO, 0, 8));

	/*
	 * Move the candidate prime q's intermediate value into IFIFO
	 */
	caam_desc_add_word(desc,
			   MOVE_WAIT(C2_CTX_REG, IFIFO,
				     hash_func->size - prime->q->length + 8,
				     prime->q->length - 16));

	/* Get the LSB of U and set the bit 0 */
	caam_desc_add_word(desc, MOVE_WAIT(C2_CTX_REG, MATH_REG0,
					   hash_func->size - 8, 8));
	caam_desc_add_word(desc, MATH(OR, ONE, REG0, REG0, 8));

	/* Move the candidate prime q's LSB into IFIFO */
	caam_desc_add_word(desc, MOVE_WAIT(MATH_REG0, IFIFO, 0, 8));

	/* Move the IFIFO in to PKHA N */
	caam_desc_add_word(desc, LD_IMM(CLASS_NO, REG_NFIFO, 8));
	caam_desc_add_word(desc, NFIFO_NOPAD(C1, NFIFO_FC1, IFIFO, PKHA_N, 0));
	caam_desc_add_word(desc, prime->q->length);

	/* Store the Prime q here because Miller-Rabin test affect PKHA N */
	caam_desc_add_word(desc, FIFO_ST(CLASS_NO, PKHA_N, prime->q->length));
	caam_desc_add_ptr(desc, prime->q->paddr);

	/*
	 * Step 8. Test q prime with 'miller-rabin' test
	 *
	 * Load the number of Miller-Rabin test iteration
	 */
	caam_desc_add_word(desc, MATH(ADD, IMM_DATA, ZERO, SIL, 4));
	if (prime->p->length <= 1024 / 8)
		caam_desc_add_word(desc, 40);
	else if (prime->p->length >= 3072 / 8)
		caam_desc_add_word(desc, 64);
	else
		caam_desc_add_word(desc, 56);

	retry_mr_test = caam_desc_get_len(desc);

	/* Generate 8 random bytes 'miller-rabin seed' */
	caam_desc_add_word(desc, LD_IMM(CLASS_NO, REG_NFIFO, 8));
	caam_desc_add_word(desc, NFIFO_PAD(C1, NFIFO_FC1, PKHA_A, RND, 0));
	caam_desc_add_word(desc, prime->q->length);
	caam_desc_add_word(desc, FIFO_LD_IMM(CLASS_1, PKHA_B, NOACTION, 1));
	caam_desc_add_word(desc, 0x01);
	caam_desc_add_word(desc, PKHA_OP(MR_PRIMER_TEST, B));

	desclen = caam_desc_get_len(desc);

	/*
	 * Step 9. If q is not q prime back to step 5
	 */
	caam_desc_add_word(desc, JUMP_CNO_LOCAL(ANY_COND_FALSE,
						JMP_COND(PKHA_IS_PRIME),
						retry_new_mr_failed - desclen));
	caam_desc_add_word(desc, MATH(SUB, SIL, ONE, SIL, 4));

	desclen = caam_desc_get_len(desc);
	/* Test while number of MR test iteration not complete */
	caam_desc_add_word(desc,
			   JUMP_CNO_LOCAL(ALL_COND_FALSE,
					  JMP_COND(MATH_N) | JMP_COND(MATH_Z),
					  retry_mr_test - desclen));
	DSA_TRACE("Prime Q descriptor");
	DSA_DUMPDESC(desc);
}

/*
 * Build the descriptor generating the intermediate value X (step 11.3)
 * Referring to FIPS.186-4, Section A.1.1.2 Generation of the
 * Probable Primes p and q Using an Approved Hash Function
 *
 * @desc        [out] Descriptor built
 * @x           [out] Value X
 * @seed        [in/out] Seed to hash and next seed for next loop
 * @prime       [in/out] Prime generation data
 * @hash_func   Selected Hash function
 * @mod_n       Modular value (0xFF filled buffer)
 * @desc_p      Physical address of the descriptor doing Prime P
 */
static void do_desc_gen_x(uint32_t *desc, struct caambuf *x,
			  struct caambuf *seed, struct prime_data_dsa *prime,
			  struct dsa_hash *hash_func, struct caambuf *mod_n,
			  paddr_t desc_p)
{
	unsigned int desclen = 0;
	unsigned int loop_n = 0;
	size_t n = 0;
	size_t b = 0;
	size_t b_offset = 0;

	/*
	 * Step 3. n = ceil(L / outlen) - 1
	 * where outlen is the hash size in bits
	 *
	 * Note build descriptor with n = ceil(L / outlen) to
	 * pre-calculate seed for next run.
	 */
	n = (prime->p->length + hash_func->size) * 8 - 1;
	n /= hash_func->size * 8;

	/*
	 * Step 4. b = L - 1 - (n  * outlen)
	 *
	 * Note b determine the number of bits to keep in the last
	 * Vn computed.
	 * Calculate b_offset which is the offset in bytes to remove from
	 * the calculated hash
	 */
	b = prime->p->length * 8 - 1 - (n - 1) * hash_func->size * 8;

	DSA_TRACE("Prime p => n = %zu | b = %zu", n - 1, b);
	b_offset = hash_func->size - (b + 1) / 8;
	DSA_TRACE("Vn offset is %zu", b_offset);

	caam_desc_init(desc);
	caam_desc_add_word(desc, DESC_HEADER(0));

	caam_desc_add_word(desc, SEQ_OUT_PTR(x->length));
	caam_desc_add_ptr(desc, x->paddr);

	caam_desc_add_word(desc, MATHI_OP1(SHIFT_L, ONE, 63, REG2, 8));

	caam_desc_add_word(desc, MATH(ADD, ZERO, IMM_DATA, REG0, 4));
	caam_desc_add_word(desc, n);

	caam_desc_add_word(desc,
			   FIFO_LD(CLASS_1, PKHA_N, NOACTION, seed->length));
	caam_desc_add_ptr(desc, mod_n->paddr);

	/*
	 * Because the Sequence Out Pointer is incremental store, we need
	 * to build w number in reverse.
	 *
	 * Hence, calculate the last seed number of the loop and save it.
	 * Step 11.9 is automatically done here by incrementing seed number.
	 */
	caam_desc_add_word(desc, FIFO_LD_IMM(CLASS_1, PKHA_B, NOACTION, 1));
	caam_desc_add_word(desc, n);
	caam_desc_add_word(desc,
			   FIFO_LD(CLASS_1, PKHA_A, NOACTION, seed->length));
	caam_desc_add_ptr(desc, seed->paddr);
	caam_desc_add_word(desc, PKHA_OP(MOD_ADD_A_B, A));
	caam_desc_add_word(desc, FIFO_ST(CLASS_NO, PKHA_A, seed->length));
	caam_desc_add_ptr(desc, seed->paddr);

	caam_desc_add_word(desc, PKHA_CPY_NSIZE(A0, B1));
	caam_desc_add_word(desc, FIFO_LD_IMM(CLASS_1, PKHA_B, NOACTION, 1));
	caam_desc_add_word(desc, 1);

	caam_desc_add_word(desc, WAIT_COND(ALL_COND_TRUE, NIFP));

	/*
	 * Step 11.1
	 * For j = 0 to n do
	 *    Vj = hash((seed + offset + j) mod 2^seedlen
	 * Step 11.2
	 *    W = V0 + (V1 * 2^outlen) + ... +
	 *        (Vn-1 * 2^((n-1)*outlen)) +
	 *        ((Vn mod 2^b) * 2^(n*outlen))
	 */
	loop_n = caam_desc_get_len(desc);

	caam_desc_add_word(desc, LD_IMM(CLASS_NO, REG_CLEAR_WRITTEN, 4));
	caam_desc_add_word(desc, CLR_WR_IFIFO_NFIFO | CLR_WR_RST_C2_CHA |
					 CLR_WR_RST_C2_DSZ);

	caam_desc_add_word(desc, HASH_INITFINAL(hash_func->op));
	caam_desc_add_word(desc, LD_NOCLASS_IMM(REG_CHA_CTRL, 4));
	caam_desc_add_word(desc, CCTRL_ULOAD_PKHA_A);

	caam_desc_add_word(desc,
			   MOVE_WAIT(OFIFO, IFIFO_C2_LC2, 0, seed->length));

	/* If Math Register 2 is zero bypass the high bit set to one */
	caam_desc_add_word(desc, MATH(SUB, REG2, ONE, NODEST, 8));
	caam_desc_add_word(desc,
			   JUMP_CNO_LOCAL(ANY_COND_TRUE,
					  JMP_COND(MATH_N) | JMP_COND(MATH_Z),
					  8));
	/*
	 * Step 11.3
	 * X = W + 2^(L-1)
	 *
	 * Set the high bit to one
	 * Remark: the DSA key is a modulus 8 bytes, hence no need
	 *         to check if the b_offset is less than 8.
	 */
	caam_desc_add_word(desc, MOVE_WAIT(C2_CTX_REG, MATH_REG1, b_offset, 8));
	caam_desc_add_word(desc, MATH(OR, REG2, REG1, REG1, 8));
	caam_desc_add_word(desc, MOVE(MATH_REG1, OFIFO, 0, 8));

	if (hash_func->size - b_offset > 8)
		caam_desc_add_word(desc,
				   MOVE_WAIT(C2_CTX_REG, OFIFO, b_offset + 8,
					     hash_func->size - b_offset - 8));
	caam_desc_add_word(desc,
			   FIFO_ST_SEQ(MSG_DATA, hash_func->size - b_offset));

	/*
	 * Reset MATH Register 2 to bypass the High Bit set
	 * operation next loop
	 */
	caam_desc_add_word(desc, MATH(AND, REG2, ZERO, REG2, 8));

	caam_desc_add_word(desc,
			   JUMP_CNO_LOCAL(ALL_COND_TRUE, JMP_COND(NONE), 2));

	/* Bypass High Bit set */
	caam_desc_add_word(desc,
			   ST_NOIMM_SEQ(CLASS_2, REG_CTX, hash_func->size));

	caam_desc_add_word(desc, PKHA_CPY_NSIZE(B1, A0));
	caam_desc_add_word(desc, PKHA_OP(MOD_SUB_A_B, A));
	caam_desc_add_word(desc, PKHA_CPY_NSIZE(A0, B1));

	desclen = caam_desc_get_len(desc);
	caam_desc_add_word(desc, JUMP_CNO_LOCAL_DEC(ALL_COND_FALSE, MATH_0,
						    JMP_COND_MATH(N) |
							    JMP_COND_MATH(Z),
						    loop_n - desclen));
	/* Jump to the next descriptor desc */
	caam_desc_add_word(desc, JUMP_NOTLOCAL(CLASS_NO, ALL_COND_TRUE,
					       JMP_COND(NONE)));
	caam_desc_add_ptr(desc, desc_p);

	DSA_TRACE("X descriptor");
	DSA_DUMPDESC(desc);
}

/*
 * Build the descriptor generating the Prime P from value X
 * Referring to FIPS.186-4, Section A.1.1.2 Generation of the
 * Probable Primes p and q Using an Approved Hash Function
 *
 * @desc        [out] Descriptor built
 * @prime       [in/out] Prime generation data
 * @x           Value X
 * @mod_n       Modular value (0xFF filled buffer)
 */
static void do_desc_prime_p(uint32_t *desc, struct prime_data_dsa *prime,
			    struct caambuf *x, struct caambuf *mod_n)
{
	unsigned int desclen = 0;
	unsigned int retry_mr_test = 0;
	size_t index = 0;

	caam_desc_init(desc);
	caam_desc_add_word(desc, DESC_HEADER(0));

	caam_desc_add_word(desc,
			   FIFO_LD(CLASS_1, PKHA_N, NOACTION, mod_n->length));
	caam_desc_add_ptr(desc, mod_n->paddr);

	/*
	 * Step 11.4
	 * c = X mod 2q
	 */

	/* Calculate 2q and store it in PKHA N */
	caam_desc_add_word(desc, FIFO_LD(CLASS_1, PKHA_A, NOACTION,
					 prime->q->length));
	caam_desc_add_ptr(desc, prime->q->paddr);
	caam_desc_add_word(desc, PKHA_CPY_SSIZE(A0, B0));
	caam_desc_add_word(desc, PKHA_OP(MOD_ADD_A_B, A));

	caam_desc_add_word(desc, PKHA_CPY_SSIZE(A0, N0));

	/* c = X mod 2q */
	caam_desc_add_word(desc, FIFO_LD(CLASS_1, PKHA_A, NOACTION, x->length));
	caam_desc_add_ptr(desc, x->paddr);
	caam_desc_add_word(desc,
			   JUMP_CNO_LOCAL(ALL_COND_TRUE, JMP_COND(NIFP), 1) |
			   BIT(24));
	caam_desc_add_word(desc, PKHA_OP(MOD_AMODN, A));

	/*
	 * Step 11.5
	 * p = X - (c - 1)
	 */
	caam_desc_add_word(desc,
			   FIFO_LD(CLASS_1, PKHA_N, NOACTION, mod_n->length));
	caam_desc_add_ptr(desc, mod_n->paddr);

	caam_desc_add_word(desc, FIFO_LD_IMM(CLASS_1, PKHA_B, NOACTION, 1));
	caam_desc_add_ptr(desc, 1);
	caam_desc_add_word(desc, PKHA_OP(MOD_SUB_A_B, B));

	caam_desc_add_word(desc, FIFO_LD(CLASS_1, PKHA_A, NOACTION, x->length));
	caam_desc_add_ptr(desc, x->paddr);
	caam_desc_add_word(desc, PKHA_OP(MOD_SUB_A_B, A));

	/*
	 * Save the candidate Prime q now because N is going to be
	 * affected by the Miller-Rabin test
	 */
	caam_desc_add_word(desc, PKHA_CPY_SSIZE(A0, N0));
	caam_desc_add_word(desc, FIFO_ST(CLASS_NO, PKHA_N, prime->p->length));
	caam_desc_add_ptr(desc, prime->p->paddr);
	caam_desc_add_word(desc, FIFO_ST_SEQ(MSG_DATA, 0));

	/*
	 * Step 11.6
	 * if (p < 2^(L-1)) then go to step 11.9
	 *
	 */
	caam_desc_add_word(desc, LD_NOCLASS_IMM(REG_CHA_CTRL, 4));
	caam_desc_add_word(desc, CCTRL_ULOAD_PKHA_A);

	/* Keep the MSB from p candidate and check if bit 2^(L-1) is set */
	caam_desc_add_word(desc, MOVE_WAIT(OFIFO, MATH_REG0, 0, 8));
	for (index = 1; index < prime->p->length / 128; index++)
		caam_desc_add_word(desc, MOVE(OFIFO, C1_CTX_REG, 0, 128));

	caam_desc_add_word(desc, MOVE(OFIFO, C1_CTX_REG, 0, 124));

	caam_desc_add_word(desc, MATHI_OP1(SHIFT_L, ONE, 63, REG2, 8));
	caam_desc_add_word(desc, MATH(AND, REG0, REG2, REG0, 8));

	caam_desc_add_word(desc, HALT_USER(ALL_COND_TRUE, MATH_Z,
					   DSA_PRIME_TOO_SMALL));

	/*
	 * Step 11.7
	 * Test whether or not p is prime
	 *
	 * Referring to FIPS.186-4, Table C.1
	 * Get the number Miller-Rabin test interation function
	 * of the prime number size
	 */
	caam_desc_add_word(desc, MATH(ADD, IMM_DATA, ZERO, REG0, 4));
	if (prime->p->length <= 1024 / 8)
		caam_desc_add_word(desc, 40);
	else if (prime->p->length >= 3072 / 8)
		caam_desc_add_word(desc, 64);
	else
		caam_desc_add_word(desc, 56);

	retry_mr_test = caam_desc_get_len(desc);
	/* Generate 8 random bytes 'miller-rabin seed' */
	caam_desc_add_word(desc, LD_IMM(CLASS_NO, REG_NFIFO, 8));
	caam_desc_add_word(desc, NFIFO_PAD(C1, NFIFO_FC1, PKHA_A, RND, 0));
	caam_desc_add_word(desc, prime->p->length);
	caam_desc_add_word(desc, FIFO_LD_IMM(CLASS_1, PKHA_B, NOACTION, 1));
	caam_desc_add_word(desc, 0x01);
	caam_desc_add_word(desc, PKHA_OP(MR_PRIMER_TEST, B));

	desclen = caam_desc_get_len(desc);

	/*
	 * Step 11.8
	 * if p is not a prime continue to step 11.9
	 */
	caam_desc_add_word(desc, HALT_USER(ALL_COND_FALSE, PKHA_IS_PRIME,
					   DSA_NOT_PRIME));

	desclen = caam_desc_get_len(desc);
	/* Test while number of MR test iteration not complete */
	caam_desc_add_word(desc, JUMP_CNO_LOCAL_DEC(ALL_COND_FALSE, MATH_0,
						    JMP_COND_MATH(N) |
						    JMP_COND_MATH(Z),
						    retry_mr_test - desclen));

	DSA_TRACE("Prime P descriptor");
	DSA_DUMPDESC(desc);

	/*
	 * Ensure descriptor is pushed in physical memory because it's
	 * called from another descriptor.
	 */
	cache_operation(TEE_CACHECLEAN, desc, DESC_SZBYTES(PRIME_DESC_ENTRIES));
}

/*
 * Run the Prime Q descriptor.
 *
 * @desc Descriptor built
 */
static enum caam_status run_prime_q(uint32_t *desc,
				    struct prime_data_dsa *prime)
{
	enum caam_status retstatus = CAAM_FAILURE;
	struct caam_jobctx jobctx = { };

	cache_operation(TEE_CACHEFLUSH, prime->q->data, prime->q->length);

	jobctx.desc = desc;
	retstatus = caam_jr_enqueue(&jobctx, NULL);

	if (retstatus != CAAM_NO_ERROR) {
		DSA_TRACE("Prime Q Status 0x%08" PRIx32 " ret 0x%08" PRIx32,
			  jobctx.status, retstatus);
		retstatus = CAAM_FAILURE;
	} else {
		cache_operation(TEE_CACHEINVALIDATE, prime->q->data,
				prime->q->length);
		DSA_DUMPBUF("Prime Q", prime->q->data, prime->q->length);
	}

	return retstatus;
}

/*
 * Run the Prime P descriptors.
 *
 * @desc   Descriptor built
 * @prime  Prime generation data
 */
static enum caam_status run_prime_p(uint32_t *desc,
				    struct prime_data_dsa *prime)
{
	enum caam_status retstatus = CAAM_FAILURE;
	struct caam_jobctx jobctx = { };
	size_t counter = 0;

	cache_operation(TEE_CACHEFLUSH, prime->p->data, prime->p->length);

	jobctx.desc = desc;
	for (counter = 0; counter < 4 * prime->p->length * 8; counter++) {
		retstatus = caam_jr_enqueue(&jobctx, NULL);

		if (retstatus == CAAM_NO_ERROR) {
			DSA_TRACE("Prime P try: counter=%zu", counter);
			cache_operation(TEE_CACHEINVALIDATE, prime->p->data,
					prime->p->length);
			DSA_DUMPBUF("Prime P", prime->p->data,
				    prime->p->length);

			return retstatus;
		}

		if (retstatus == CAAM_JOB_STATUS) {
			if (JRSTA_GET_HALT_USER(jobctx.status) !=
				    DSA_NOT_PRIME &&
			    JRSTA_GET_HALT_USER(jobctx.status) !=
				    DSA_PRIME_TOO_SMALL) {
				DSA_TRACE("Prime P status 0x%08" PRIx32,
					  jobctx.status);
				return CAAM_FAILURE;
			}
		}
	}

	/* This is not a prime, will try with another prime q */
	return CAAM_BAD_PARAM;
}

/*
 * Generate the DSA parameter G (generator)
 * Referring to FIPS.186-4, Section A.2.1 Unverifiable Generation of the
 * Generator g
 *
 * @desc        Descriptor buffer to use
 * @prime       [in/out] Prime generation data
 * @mod_n       Modular value (0xFF filled buffer)
 */
static enum caam_status do_generator(uint32_t *desc,
				     struct prime_data_dsa *prime,
				     struct caambuf *mod_n)
{
	enum caam_status retstatus = CAAM_FAILURE;
	struct caam_jobctx jobctx = { };
	unsigned int desclen = 0;
	unsigned int retry_new_h = 0;

	caam_desc_init(desc);
	caam_desc_add_word(desc, DESC_HEADER(0));

	caam_desc_add_word(desc,
			   FIFO_LD(CLASS_1, PKHA_N, NOACTION, mod_n->length));
	caam_desc_add_ptr(desc, mod_n->paddr);

	/*
	 * Step 1.
	 * e = (p - 1)/q
	 */
	caam_desc_add_word(desc, FIFO_LD(CLASS_1, PKHA_A, NOACTION,
					 prime->p->length));
	caam_desc_add_ptr(desc, prime->p->paddr);
	caam_desc_add_word(desc, FIFO_LD_IMM(CLASS_1, PKHA_B, NOACTION, 1));
	caam_desc_add_ptr(desc, 1);
	/* PKHA B = (p - 1) */
	caam_desc_add_word(desc, PKHA_OP(MOD_SUB_A_B, B));

	caam_desc_add_word(desc, FIFO_LD(CLASS_1, PKHA_A, NOACTION,
					 prime->q->length));
	caam_desc_add_ptr(desc, prime->q->paddr);
	/* PKHA A = 1/q */
	caam_desc_add_word(desc, PKHA_OP(MOD_INV_A, A));

	/* PKHA E = (p - 1)/q */
	caam_desc_add_word(desc, PKHA_OP(MOD_MUL_A_B, A));
	caam_desc_add_word(desc, PKHA_CPY_SSIZE(A0, E));

	/* Load N with prime p */
	caam_desc_add_word(desc, FIFO_LD(CLASS_1, PKHA_N, NOACTION,
					 prime->p->length));
	caam_desc_add_ptr(desc, prime->p->paddr);

	/*
	 * Step 2. Generate a Random h
	 * where 1 < h < (p - 1)
	 *
	 * To ensure h < (p - 1), generate a random of p length - 2
	 */
	retry_new_h = caam_desc_get_len(desc);
	caam_desc_add_word(desc, LD_IMM(CLASS_NO, REG_NFIFO, 8));
	caam_desc_add_word(desc, NFIFO_PAD(C1, NFIFO_FC1, PKHA_A, RND, 0));
	caam_desc_add_word(desc, prime->p->length - 2);

	/*
	 * Step 3.
	 * g = h^e mod p
	 */
	caam_desc_add_word(desc, PKHA_OP(MOD_EXP_A_E, A));

	/*
	 * Step 4.
	 * if (g = 1) then go to step 2
	 */
	desclen = caam_desc_get_len(desc);
	caam_desc_add_word(desc,
			   JUMP_CNO_LOCAL(ALL_COND_TRUE, JMP_COND(PKHA_GCD_1),
					  retry_new_h - desclen));

	/* g is good save it */
	caam_desc_add_word(desc, FIFO_ST(CLASS_NO, PKHA_A, prime->g->length));
	caam_desc_add_ptr(desc, prime->g->paddr);

	DSA_DUMPDESC(desc);

	cache_operation(TEE_CACHEFLUSH, prime->g->data, prime->g->length);

	jobctx.desc = desc;
	retstatus = caam_jr_enqueue(&jobctx, NULL);

	if (retstatus != CAAM_NO_ERROR) {
		DSA_TRACE("Generator G Status 0x%08" PRIx32 " ret 0x%08" PRIx32,
			  jobctx.status, retstatus);
		return CAAM_FAILURE;
	}

	cache_operation(TEE_CACHEINVALIDATE, prime->g->data, prime->g->length);
	DSA_DUMPBUF("Generator G", prime->g->data, prime->g->length);

	return CAAM_NO_ERROR;
}

enum caam_status caam_prime_dsa_gen(struct prime_data_dsa *data)
{
	enum caam_status retstatus = CAAM_FAILURE;
	uint32_t *desc_all = NULL;
	uint32_t *desc_q = NULL;
	uint32_t *desc_x = NULL;
	uint32_t *desc_p = NULL;
	struct caambuf seed = { };
	struct caambuf mod_n = { };
	struct dsa_hash hash_func = { OP_ALGO(SHA256), TEE_SHA256_HASH_SIZE };
	size_t nb_tries = 0;
	struct caambuf x = { };

	/*
	 * For the now as the DSA Prime p size is limited to 3072, Prime q
	 * is also limited to 256. Hence the hash function to use is
	 * SHA-256.
	 * Ensure here that limit is not crossed because on some i.MX device
	 * hash is limited to 256.
	 */
	if (data->q->length > 256)
		return CAAM_BAD_PARAM;

	retstatus = caam_calloc_buf(&mod_n, data->p->length);
	if (retstatus != CAAM_NO_ERROR)
		goto out;

	memset(mod_n.data, 0xFF, mod_n.length);
	cache_operation(TEE_CACHECLEAN, mod_n.data, mod_n.length);

	retstatus = caam_calloc_align_buf(&seed, data->q->length);
	if (retstatus != CAAM_NO_ERROR)
		return retstatus;

	retstatus = caam_calloc_buf(&x, data->p->length);
	if (retstatus != CAAM_NO_ERROR)
		return retstatus;

	desc_all = caam_calloc_desc(PRIME_DESC_ENTRIES * 3);
	if (!desc_all) {
		retstatus = CAAM_OUT_MEMORY;
		goto out;
	}

	DSA_TRACE("Do primes P %zu bytes, Q %zu bytes", data->p->length,
		  data->q->length);

	desc_q = desc_all;
	desc_x = desc_q + PRIME_DESC_ENTRIES;
	desc_p = desc_x + PRIME_DESC_ENTRIES;

	do_desc_prime_q(desc_q, &seed, data, &hash_func);
	do_desc_gen_x(desc_x, &x, &seed, data, &hash_func, &mod_n,
		      virt_to_phys(desc_p));
	do_desc_prime_p(desc_p, data, &x, &mod_n);

	cache_operation(TEE_CACHEFLUSH, data->p->data, data->p->length);
	cache_operation(TEE_CACHEFLUSH, seed.data, seed.length);
	cache_operation(TEE_CACHEFLUSH, x.data, x.length);

	for (nb_tries = DSA_MAX_TRIES_PRIME_P; nb_tries > 0; nb_tries--) {
		retstatus = run_prime_q(desc_q, data);

		if (retstatus == CAAM_NO_ERROR) {
			retstatus = run_prime_p(desc_x, data);
			if (retstatus == CAAM_NO_ERROR)
				break;
		}

		if (retstatus == CAAM_FAILURE) {
			DSA_TRACE("DSA Prime P/Q Generation failed");
			break;
		}
	}

	if (retstatus == CAAM_NO_ERROR)
		retstatus = do_generator(desc_all, data, &mod_n);

out:
	caam_free_desc(&desc_all);
	caam_free_buf(&seed);
	caam_free_buf(&x);
	caam_free_buf(&mod_n);

	return retstatus;
}
