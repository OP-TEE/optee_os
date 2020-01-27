// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2018, Linaro Limited */

/*
 * This is an implementation of the Fortuna cryptographic PRNG as defined in
 * https://www.schneier.com/academic/paperfiles/fortuna.pdf
 * There's one small exception, see comment in restart_pool() below.
 */

#include <assert.h>
#include <crypto/crypto.h>
#include <kernel/mutex.h>
#include <kernel/refcount.h>
#include <kernel/spinlock.h>
#include <kernel/tee_time.h>
#include <string.h>
#include <types_ext.h>
#include <utee_defines.h>
#include <util.h>

#define NUM_POOLS		32
#define BLOCK_SIZE		16
#define KEY_SIZE		32
#define CIPHER_ALGO		TEE_ALG_AES_ECB_NOPAD
#define HASH_ALGO		TEE_ALG_SHA256
#define MIN_POOL_SIZE		64
#define MAX_EVENT_DATA_LEN	32U
#define RING_BUF_DATA_SIZE	4U

/*
 * struct fortuna_state - state of the Fortuna PRNG
 * @ctx:		Cipher context used to produce the random numbers
 * @counter:		Counter which is encrypted to produce the random numbers
 * @pool0_length:	Amount of data added to pool0
 * @pool_ctx:		One hash context for each pool
 * @reseed_ctx:		Hash context used while reseeding
 * @reseed_count:	Number of time we've reseeded the PRNG, used to tell
 *			which pools should be used in the reseed process
 * @next_reseed_time:	If we have a secure time, the earliest next time we
 *			may reseed
 *
 * To minimize the delay in crypto_rng_add_event() there's @pool_spin_lock
 * which protects everything needed by this function.
 *
 * @next_reseed_time is used as a rate limiter for reseeding.
 */
static struct fortuna_state {
	void *ctx;
	uint64_t counter[2];
	unsigned int pool0_length;
	void *pool_ctx[NUM_POOLS];
	void *reseed_ctx;
	uint32_t reseed_count;
#ifndef CFG_SECURE_TIME_SOURCE_REE
	TEE_Time next_reseed_time;
#endif
} state;

static struct mutex state_mu = MUTEX_INITIALIZER;

static struct {
	struct {
		uint8_t snum;
		uint8_t pnum;
		uint8_t dlen;
		uint8_t data[RING_BUF_DATA_SIZE];
	} elem[8];
	unsigned int begin;
	unsigned int end;
} ring_buffer;

unsigned int ring_buffer_spin_lock;

static void inc_counter(uint64_t counter[2])
{
	counter[0]++;
	if (!counter[0])
		counter[1]++;
}

static TEE_Result hash_init(void *ctx)
{
	return crypto_hash_init(ctx);
}

static TEE_Result hash_update(void *ctx, const void *data, size_t dlen)
{
	return crypto_hash_update(ctx, data, dlen);
}

static TEE_Result hash_final(void *ctx, uint8_t digest[KEY_SIZE])
{
	return crypto_hash_final(ctx, digest, KEY_SIZE);
}

static TEE_Result key_from_data(void *ctx, const void *data, size_t dlen,
				uint8_t key[KEY_SIZE])
{
	TEE_Result res;

	res = hash_init(ctx);
	if (res)
		return res;
	res = hash_update(ctx, data, dlen);
	if (res)
		return res;
	return hash_final(ctx, key);
}

static TEE_Result cipher_init(void *ctx, uint8_t key[KEY_SIZE])
{
	return crypto_cipher_init(ctx, TEE_MODE_ENCRYPT,
				  key, KEY_SIZE, NULL, 0, NULL, 0);
}

static void fortuna_done(void)
{
	size_t n;

	for (n = 0; n < NUM_POOLS; n++) {
		crypto_hash_free_ctx(state.pool_ctx[n]);
		state.pool_ctx[n] = NULL;
	}
	crypto_hash_free_ctx(state.reseed_ctx);
	state.reseed_ctx = NULL;
	crypto_cipher_free_ctx(state.ctx);
	state.ctx = NULL;
}

TEE_Result crypto_rng_init(const void *data, size_t dlen)
{
	TEE_Result res;
	uint8_t key[KEY_SIZE];
	void *ctx;
	size_t n;

	COMPILE_TIME_ASSERT(sizeof(state.counter) == BLOCK_SIZE);

	if (state.ctx)
		return TEE_ERROR_BAD_STATE;

	memset(&state, 0, sizeof(state));

	for (n = 0; n < NUM_POOLS; n++) {
		res = crypto_hash_alloc_ctx(&state.pool_ctx[n], HASH_ALGO);
		if (res)
			goto err;
		res = crypto_hash_init(state.pool_ctx[n]);
		if (res)
			goto err;
	}

	res = crypto_hash_alloc_ctx(&state.reseed_ctx, HASH_ALGO);
	if (res)
		goto err;

	res = key_from_data(state.reseed_ctx, data, dlen, key);
	if (res)
		return res;

	res = crypto_cipher_alloc_ctx(&ctx, CIPHER_ALGO);
	if (res)
		return res;
	res = cipher_init(ctx, key);
	if (res)
		return res;
	inc_counter(state.counter);
	state.ctx = ctx;
	return TEE_SUCCESS;
err:
	fortuna_done();
	return res;
}

static void push_ring_buffer(uint8_t snum, uint8_t pnum, const void *data,
			     size_t dlen)
{
	uint8_t dl = MIN(RING_BUF_DATA_SIZE, dlen);
	unsigned int next_begin;
	uint32_t old_itr_status;

	/* Spinlock to serialize writers */
	old_itr_status = cpu_spin_lock_xsave(&ring_buffer_spin_lock);

	next_begin = (ring_buffer.begin + 1) % ARRAY_SIZE(ring_buffer.elem);
	if (next_begin == atomic_load_uint(&ring_buffer.end))
		goto out; /* buffer is full */

	ring_buffer.elem[next_begin].snum = snum;
	ring_buffer.elem[next_begin].pnum = pnum;
	ring_buffer.elem[next_begin].dlen = dl;
	memcpy(ring_buffer.elem[next_begin].data, data, dl);

	atomic_store_uint(&ring_buffer.begin, next_begin);

out:
	cpu_spin_unlock_xrestore(&ring_buffer_spin_lock, old_itr_status);
}

static size_t pop_ring_buffer(uint8_t *snum, uint8_t *pnum,
			      uint8_t data[RING_BUF_DATA_SIZE])
{
	unsigned int next_end;
	size_t dlen;

	if (atomic_load_uint(&ring_buffer.begin) == ring_buffer.end)
		return 0;

	next_end = (ring_buffer.end + 1) % ARRAY_SIZE(ring_buffer.elem);

	*snum = ring_buffer.elem[ring_buffer.end].snum;
	*pnum = ring_buffer.elem[ring_buffer.end].pnum;
	dlen = MIN(ring_buffer.elem[ring_buffer.end].dlen, RING_BUF_DATA_SIZE);
	assert(ring_buffer.elem[ring_buffer.end].dlen == dlen);
	memcpy(data, ring_buffer.elem[ring_buffer.end].data, dlen);

	atomic_store_uint(&ring_buffer.end, next_end);

	return dlen;
}

static TEE_Result add_event(uint8_t snum, uint8_t pnum,
			    const void *data, size_t dlen)
{
	TEE_Result res;
	size_t dl = MIN(MAX_EVENT_DATA_LEN, dlen);
	uint8_t v[] = { snum, dl };

	if (pnum >= NUM_POOLS)
		return TEE_ERROR_BAD_PARAMETERS;

	res = hash_update(state.pool_ctx[pnum], v, sizeof(v));
	if (res)
		return res;
	res = hash_update(state.pool_ctx[pnum], data, dl);
	if (res)
		return res;
	if (!pnum) {
		unsigned int l;

		if (!ADD_OVERFLOW(state.pool0_length, dl, &l))
			state.pool0_length = l;
	}

	return TEE_SUCCESS;
}

static TEE_Result drain_ring_buffer(void)
{
	while (true) {
		TEE_Result res;
		uint8_t snum;
		uint8_t pnum;
		uint8_t data[RING_BUF_DATA_SIZE];
		size_t dlen;

		dlen = pop_ring_buffer(&snum, &pnum, data);
		if (!dlen)
			return TEE_SUCCESS;

		res = add_event(snum, pnum, data, dlen);
		if (res)
			return res;
	}
}

static unsigned int get_next_pnum(unsigned int *pnum)
{
	unsigned int nval;
	unsigned int oval = atomic_load_uint(pnum);

	while (true) {
		nval = (oval + 1) % NUM_POOLS;

		if (atomic_cas_uint(pnum, &oval, nval)) {
			/*
			 * *pnum is normally initialized to 0 and we'd like
			 * to start feeding pool number 0 as that's the
			 * most important one.
			 *
			 * If we where to take just *pnum and increase it
			 * later multiple updaters could end up with the
			 * same number.
			 *
			 * By increasing first we get the number unique for
			 * next update and by subtracting one (using
			 * modulus) we get the number for this update.
			 */
			return (nval + NUM_POOLS - 1) % NUM_POOLS;
		}
		/*
		 * At this point atomic_cas_uint() has updated oval to the
		 * current *pnum.
		 */
	}
}

void crypto_rng_add_event(enum crypto_rng_src sid, unsigned int *pnum,
			  const void *data, size_t dlen)
{
	unsigned int pn = get_next_pnum(pnum);
	uint8_t snum = sid >> 1;

	if (CRYPTO_RNG_SRC_IS_QUICK(sid)) {
		push_ring_buffer(snum, pn, data, dlen);
	} else {
		mutex_lock(&state_mu);
		add_event(snum, pn, data, dlen);
		drain_ring_buffer();
		mutex_unlock(&state_mu);
	}
}

/* GenerateBlocks */
static TEE_Result generate_blocks(void *block, size_t nblocks)
{
	uint8_t *b = block;
	size_t n;

	for (n = 0; n < nblocks; n++) {
		TEE_Result res = crypto_cipher_update(state.ctx,
						      TEE_MODE_ENCRYPT, false,
						      (void *)state.counter,
						      BLOCK_SIZE,
						      b + n * BLOCK_SIZE);

		/*
		 * Make sure to increase the counter before returning an
		 * eventual errors, we must never re-use the counter with
		 * the same key.
		 */
		inc_counter(state.counter);
		if (res)
			return res;
	}

	return TEE_SUCCESS;
}

/* GenerateRandomData */
static TEE_Result generate_random_data(void *buf, size_t blen)
{
	TEE_Result res;

	res = generate_blocks(buf, blen / BLOCK_SIZE);
	if (res)
		return res;
	if (blen % BLOCK_SIZE) {
		uint8_t block[BLOCK_SIZE];
		uint8_t *b = (uint8_t *)buf + ROUNDDOWN(blen, BLOCK_SIZE);

		res = generate_blocks(block, 1);
		if (res)
			return res;
		memcpy(b, block, blen % BLOCK_SIZE);
	}

	return TEE_SUCCESS;
}

#ifdef CFG_SECURE_TIME_SOURCE_REE
static bool reseed_rate_limiting(void)
{
	/*
	 * There's no point in checking REE time for reseed rate limiting,
	 * and also it makes it less complicated if we can avoid doing RPC
	 * here.
	 */
	return false;
}
#else
static bool reseed_rate_limiting(void)
{
	TEE_Result res;
	TEE_Time time;
	const TEE_Time time_100ms = { 0, 100 };

	res = tee_time_get_sys_time(&time);
	/*
	 * Failure to read time must result in allowing reseed or we could
	 * block reseeding forever.
	 */
	if (res)
		return false;

	if (TEE_TIME_LT(time, state.next_reseed_time))
		return true;

	/* Time to reseed, calculate next time reseed is OK */
	TEE_TIME_ADD(time, time_100ms, state.next_reseed_time);
	return false;
}
#endif

static TEE_Result restart_pool(void *pool_ctx, uint8_t pool_digest[KEY_SIZE])
{
	TEE_Result res = hash_final(pool_ctx, pool_digest);

	if (res)
		return res;

	res = hash_init(pool_ctx);
	if (res)
		return res;

	/*
	 * Restart the pool with the digest of the old pool. This is an
	 * extension to Fortuna. In the original Fortuna all pools was
	 * restarted from scratch. This extension is one more defense
	 * against spamming of the pools with known data which could lead
	 * to the spammer knowing the state of the pools.
	 *
	 * This extra precaution could be useful since OP-TEE sometimes
	 * have very few sources of good entropy and at the same time has
	 * sources that could quite easily be predicted by an attacker.
	 */
	return hash_update(pool_ctx, pool_digest, KEY_SIZE);
}

static bool reseed_from_pool(uint32_t reseed_count, size_t pool_num)
{
	/*
	 * Specification says: use pool if
	 * 2^pool_num is a divisor of reseed_count
	 *
	 * in order to avoid an expensive modulus operation we're
	 * optimizing this below.
	 */
	return !pool_num || !((reseed_count >> (pool_num - 1)) & 1);
}

static TEE_Result maybe_reseed(void)
{
	TEE_Result res;
	size_t n;
	uint8_t pool_digest[KEY_SIZE];

	if (state.pool0_length < MIN_POOL_SIZE)
		return TEE_SUCCESS;

	if (reseed_rate_limiting())
		return TEE_SUCCESS;

	state.reseed_count++;

	res = hash_init(state.reseed_ctx);
	if (res)
		return res;

	for (n = 0;
	     n < NUM_POOLS && reseed_from_pool(state.reseed_count, n); n++) {
		res = restart_pool(state.pool_ctx[n], pool_digest);
		if (res)
			return res;
		if (!n)
			state.pool0_length = 0;

		res = hash_update(state.reseed_ctx, pool_digest, KEY_SIZE);
		if (res)
			return res;
	}
	res = hash_final(state.reseed_ctx, pool_digest);
	if (res)
		return res;

	crypto_cipher_final(state.ctx);
	res = crypto_cipher_init(state.ctx, TEE_MODE_ENCRYPT,
				 pool_digest, KEY_SIZE, NULL, 0, NULL, 0);
	if (res)
		return res;
	inc_counter(state.counter);

	return TEE_SUCCESS;
}

static TEE_Result fortuna_read(void *buf, size_t blen)
{
	TEE_Result res;

	if (!state.ctx)
		return TEE_ERROR_BAD_STATE;

	mutex_lock(&state_mu);

	res = maybe_reseed();
	if (res)
		goto out;

	if (blen) {
		uint8_t new_key[KEY_SIZE];

		res = generate_random_data(buf, blen);
		if (res)
			goto out;

		res = generate_blocks(new_key, KEY_SIZE / BLOCK_SIZE);
		if (res)
			goto out;
		crypto_cipher_final(state.ctx);
		res = cipher_init(state.ctx, new_key);
		if (res)
			goto out;
	}

	res = drain_ring_buffer();
out:
	if (res)
		fortuna_done();
	mutex_unlock(&state_mu);

	return res;
}

TEE_Result crypto_rng_read(void *buf, size_t blen)
{
	size_t offs = 0;

	while (true) {
		TEE_Result res;
		size_t n;

		/* Draw at most 1 MiB of random on a single key */
		n = MIN(blen - offs, SIZE_1M);
		if (!n)
			return TEE_SUCCESS;
		res = fortuna_read((uint8_t *)buf + offs, n);
		if (res)
			return res;
		offs += n;
	}
}
