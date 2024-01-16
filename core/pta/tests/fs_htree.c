// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2017, Linaro Limited
 */

#include <assert.h>
#include <kernel/ts_manager.h>
#include <string.h>
#include <tee/fs_htree.h>
#include <tee/tee_fs_rpc.h>
#include <trace.h>
#include <types_ext.h>
#include <util.h>

#include "misc.h"

/*
 * The smallest blocks size that can hold two struct
 * tee_fs_htree_node_image or two struct tee_fs_htree_image.
 */
#define TEST_BLOCK_SIZE		144

struct test_aux {
	uint8_t *data;
	size_t data_len;
	size_t data_alloced;
	uint8_t *block;
};

static TEE_Result test_get_offs_size(enum tee_fs_htree_type type, size_t idx,
				     uint8_t vers, size_t *offs, size_t *size)
{
	const size_t node_size = sizeof(struct tee_fs_htree_node_image);
	const size_t block_nodes = TEST_BLOCK_SIZE / (node_size * 2);
	size_t pbn = 0;
	size_t bidx = 0;

	COMPILE_TIME_ASSERT(TEST_BLOCK_SIZE >
			    sizeof(struct tee_fs_htree_node_image) * 2);
	COMPILE_TIME_ASSERT(TEST_BLOCK_SIZE >
			    sizeof(struct tee_fs_htree_image) * 2);

	assert(vers == 0 || vers == 1);

	/*
	 * File layout
	 *
	 * phys block 0:
	 * tee_fs_htree_image vers 0 @ offs = 0
	 * tee_fs_htree_image vers 1 @ offs = sizeof(tee_fs_htree_image)
	 *
	 * phys block 1:
	 * tee_fs_htree_node_image 0  vers 0 @ offs = 0
	 * tee_fs_htree_node_image 0  vers 1 @ offs = node_size
	 *
	 * phys block 2:
	 * data block 0 vers 0
	 *
	 * phys block 3:
	 * tee_fs_htree_node_image 1  vers 0 @ offs = 0
	 * tee_fs_htree_node_image 1  vers 1 @ offs = node_size
	 *
	 * phys block 4:
	 * data block 0 vers 1
	 *
	 * ...
	 */

	switch (type) {
	case TEE_FS_HTREE_TYPE_HEAD:
		*offs = sizeof(struct tee_fs_htree_image) * vers;
		*size = sizeof(struct tee_fs_htree_image);
		return TEE_SUCCESS;
	case TEE_FS_HTREE_TYPE_NODE:
		pbn = 1 + ((idx / block_nodes) * block_nodes * 2);
		*offs = pbn * TEST_BLOCK_SIZE +
			2 * node_size * (idx % block_nodes) +
			node_size * vers;
		*size = node_size;
		return TEE_SUCCESS;
	case TEE_FS_HTREE_TYPE_BLOCK:
		bidx = 2 * idx + vers;
		pbn = 2 + bidx + bidx / (block_nodes * 2 - 1);
		*offs = pbn * TEST_BLOCK_SIZE;
		*size = TEST_BLOCK_SIZE;
		return TEE_SUCCESS;
	default:
		return TEE_ERROR_GENERIC;
	}
}

static TEE_Result test_read_init(void *aux, struct tee_fs_rpc_operation *op,
				 enum tee_fs_htree_type type, size_t idx,
				 uint8_t vers, void **data)
{
	TEE_Result res = TEE_SUCCESS;
	struct test_aux *a = aux;
	size_t offs = 0;
	size_t sz = 0;

	res = test_get_offs_size(type, idx, vers, &offs, &sz);
	if (res == TEE_SUCCESS) {
		memset(op, 0, sizeof(*op));
		op->params[0].u.value.a = (vaddr_t)aux;
		op->params[0].u.value.b = offs;
		op->params[0].u.value.c = sz;
		*data = a->block;
	}

	return res;
}

static void *uint_to_ptr(uintptr_t p)
{
	return (void *)p;
}

static TEE_Result test_read_final(struct tee_fs_rpc_operation *op,
				  size_t *bytes)
{
	struct test_aux *a = uint_to_ptr(op->params[0].u.value.a);
	size_t offs = op->params[0].u.value.b;
	size_t sz = op->params[0].u.value.c;

	if (offs + sz <= a->data_len)
		*bytes = sz;
	else if (offs <= a->data_len)
		*bytes = a->data_len - offs;
	else
		*bytes = 0;

	memcpy(a->block, a->data + offs, *bytes);
	return TEE_SUCCESS;
}

static TEE_Result test_write_init(void *aux, struct tee_fs_rpc_operation *op,
				  enum tee_fs_htree_type type, size_t idx,
				  uint8_t vers, void **data)
{
	return test_read_init(aux, op, type, idx, vers, data);
}

static TEE_Result test_write_final(struct tee_fs_rpc_operation *op)
{
	struct test_aux *a = uint_to_ptr(op->params[0].u.value.a);
	size_t offs = op->params[0].u.value.b;
	size_t sz = op->params[0].u.value.c;
	size_t end = offs + sz;

	if (end > a->data_alloced) {
		EMSG("out of bounds");
		return TEE_ERROR_GENERIC;
	}

	memcpy(a->data + offs, a->block, sz);
	if (end > a->data_len)
		a->data_len = end;
	return TEE_SUCCESS;

}

static const struct tee_fs_htree_storage test_htree_ops = {
	.block_size = TEST_BLOCK_SIZE,
	.rpc_read_init = test_read_init,
	.rpc_read_final = test_read_final,
	.rpc_write_init = test_write_init,
	.rpc_write_final = test_write_final,
};

#define CHECK_RES(res, cleanup)						\
		do {							\
			TEE_Result _res = (res);			\
									\
			if (_res != TEE_SUCCESS) {			\
				EMSG("error: res = %#" PRIx32, _res);	\
				{ cleanup; }				\
			}						\
		} while (0)

static uint32_t val_from_bn_n_salt(size_t bn, size_t n, uint8_t salt)
{
	assert(bn < UINT16_MAX);
	assert(n < UINT8_MAX);
	return SHIFT_U32(n, 16) | SHIFT_U32(bn, 8) | salt;
}

static TEE_Result write_block(struct tee_fs_htree **ht, size_t bn, uint8_t salt)
{
	uint32_t b[TEST_BLOCK_SIZE / sizeof(uint32_t)] = { 0 };
	size_t n = 0;

	for (n = 0; n < ARRAY_SIZE(b); n++)
		b[n] = val_from_bn_n_salt(bn, n, salt);

	return tee_fs_htree_write_block(ht, bn, b);
}

static TEE_Result read_block(struct tee_fs_htree **ht, size_t bn, uint8_t salt)
{
	TEE_Result res = TEE_SUCCESS;
	uint32_t b[TEST_BLOCK_SIZE / sizeof(uint32_t)] = { 0 };
	size_t n = 0;

	res = tee_fs_htree_read_block(ht, bn, b);
	if (res != TEE_SUCCESS)
		return res;

	for (n = 0; n < ARRAY_SIZE(b); n++) {
		if (b[n] != val_from_bn_n_salt(bn, n, salt)) {
			DMSG("Unpected b[%zu] %#" PRIx32
			     "(expected %#" PRIx32 ")",
			     n, b[n], val_from_bn_n_salt(bn, n, salt));
			return TEE_ERROR_TIME_NOT_SET;
		}
	}

	return TEE_SUCCESS;
}

static TEE_Result do_range(TEE_Result (*fn)(struct tee_fs_htree **ht,
					    size_t bn, uint8_t salt),
			   struct tee_fs_htree **ht, size_t begin,
			   size_t num_blocks, size_t salt)
{
	TEE_Result res = TEE_SUCCESS;
	size_t n = 0;

	for (n = 0; n < num_blocks; n++) {
		res = fn(ht, n + begin, salt);
		CHECK_RES(res, goto out);
	}

out:
	return res;
}

static TEE_Result do_range_backwards(TEE_Result (*fn)(struct tee_fs_htree **ht,
						      size_t bn, uint8_t salt),
				     struct tee_fs_htree **ht, size_t begin,
				     size_t num_blocks, size_t salt)
{
	TEE_Result res = TEE_SUCCESS;
	size_t n = 0;

	for (n = 0; n < num_blocks; n++) {
		res = fn(ht, num_blocks - 1 - n + begin, salt);
		CHECK_RES(res, goto out);
	}

out:
	return res;
}

static TEE_Result htree_test_rewrite(struct test_aux *aux, size_t num_blocks,
				     size_t w_unsync_begin, size_t w_unsync_num)
{
	struct ts_session *sess = ts_get_current_session();
	const TEE_UUID *uuid = &sess->ctx->uuid;
	TEE_Result res = TEE_SUCCESS;
	struct tee_fs_htree *ht = NULL;
	size_t salt = 23;
	uint8_t hash[TEE_FS_HTREE_HASH_SIZE] = { 0 };

	assert((w_unsync_begin + w_unsync_num) <= num_blocks);

	aux->data_len = 0;
	memset(aux->data, 0xce, aux->data_alloced);

	res = tee_fs_htree_open(true, hash, 0, uuid, &test_htree_ops, aux, &ht);
	CHECK_RES(res, goto out);

	/*
	 * Intialize all blocks and verify that they read back as
	 * expected.
	 */
	res = do_range(write_block, &ht, 0, num_blocks, salt);
	CHECK_RES(res, goto out);

	res = do_range(read_block, &ht, 0, num_blocks, salt);
	CHECK_RES(res, goto out);

	/*
	 * Write all blocks again, but starting from the end using a new
	 * salt, then verify that that read back as expected.
	 */
	salt++;
	res = do_range_backwards(write_block, &ht, 0, num_blocks, salt);
	CHECK_RES(res, goto out);

	res = do_range(read_block, &ht, 0, num_blocks, salt);
	CHECK_RES(res, goto out);

	/*
	 * Use a new salt to write all blocks once more and verify that
	 * they read back as expected.
	 */
	salt++;
	res = do_range(write_block, &ht, 0, num_blocks, salt);
	CHECK_RES(res, goto out);

	res = do_range(read_block, &ht, 0, num_blocks, salt);
	CHECK_RES(res, goto out);

	/*
	 * Sync the changes of the nodes to memory, verify that all
	 * blocks are read back as expected.
	 */
	res = tee_fs_htree_sync_to_storage(&ht, hash, NULL);
	CHECK_RES(res, goto out);

	res = do_range(read_block, &ht, 0, num_blocks, salt);
	CHECK_RES(res, goto out);

	/*
	 * Close and reopen the hash-tree
	 */
	tee_fs_htree_close(&ht);
	res = tee_fs_htree_open(false, hash, 0, uuid, &test_htree_ops, aux,
				&ht);
	CHECK_RES(res, goto out);

	/*
	 * Verify that all blocks are read as expected.
	 */
	res = do_range(read_block, &ht, 0, num_blocks, salt);
	CHECK_RES(res, goto out);

	/*
	 * Rewrite a few blocks and verify that all blocks are read as
	 * expected.
	 */
	res = do_range_backwards(write_block, &ht, w_unsync_begin, w_unsync_num,
				 salt + 1);
	CHECK_RES(res, goto out);

	res = do_range(read_block, &ht, 0, w_unsync_begin, salt);
	CHECK_RES(res, goto out);
	res = do_range(read_block, &ht, w_unsync_begin, w_unsync_num, salt + 1);
	CHECK_RES(res, goto out);
	res = do_range(read_block, &ht, w_unsync_begin + w_unsync_num,
			num_blocks - (w_unsync_begin + w_unsync_num), salt);
	CHECK_RES(res, goto out);

	/*
	 * Rewrite the blocks from above again with another salt and
	 * verify that they are read back as expected.
	 */
	res = do_range(write_block, &ht, w_unsync_begin, w_unsync_num,
		       salt + 2);
	CHECK_RES(res, goto out);

	res = do_range(read_block, &ht, 0, w_unsync_begin, salt);
	CHECK_RES(res, goto out);
	res = do_range(read_block, &ht, w_unsync_begin, w_unsync_num, salt + 2);
	CHECK_RES(res, goto out);
	res = do_range(read_block, &ht, w_unsync_begin + w_unsync_num,
			num_blocks - (w_unsync_begin + w_unsync_num), salt);
	CHECK_RES(res, goto out);

	/*
	 * Skip tee_fs_htree_sync_to_storage() and call
	 * tee_fs_htree_close() directly to undo the changes since last
	 * call to tee_fs_htree_sync_to_storage().  Reopen the hash-tree
	 * and verify that recent changes indeed was discarded.
	 */
	tee_fs_htree_close(&ht);
	res = tee_fs_htree_open(false, hash, 0, uuid, &test_htree_ops, aux,
				&ht);
	CHECK_RES(res, goto out);

	res = do_range(read_block, &ht, 0, num_blocks, salt);
	CHECK_RES(res, goto out);

	/*
	 * Close, reopen and verify that all blocks are read as expected
	 * again but this time based on the counter value in struct
	 * tee_fs_htree_image.
	 */
	tee_fs_htree_close(&ht);
	res = tee_fs_htree_open(false, NULL, 0, uuid, &test_htree_ops, aux,
				&ht);
	CHECK_RES(res, goto out);

	res = do_range(read_block, &ht, 0, num_blocks, salt);
	CHECK_RES(res, goto out);

out:
	tee_fs_htree_close(&ht);
	/*
	 * read_block() returns TEE_ERROR_TIME_NOT_SET in case unexpected
	 * data is read.
	 */
	if (res == TEE_ERROR_TIME_NOT_SET)
		res = TEE_ERROR_SECURITY;
	return res;
}

static void aux_free(struct test_aux *aux)
{
	if (aux) {
		free(aux->data);
		free(aux->block);
		free(aux);
	}
}

static struct test_aux *aux_alloc(size_t num_blocks)
{
	struct test_aux *aux = NULL;
	size_t o = 0;
	size_t sz = 0;

	if (test_get_offs_size(TEE_FS_HTREE_TYPE_BLOCK, num_blocks, 1, &o, &sz))
		return NULL;

	aux = calloc(1, sizeof(*aux));
	if (!aux)
		return NULL;

	aux->data_alloced = o + sz;
	aux->data = malloc(aux->data_alloced);
	if (!aux->data)
		goto err;

	aux->block = malloc(TEST_BLOCK_SIZE);
	if (!aux->block)
		goto err;

	return aux;
err:
	aux_free(aux);
	return NULL;

}

static TEE_Result test_write_read(size_t num_blocks)
{
	struct test_aux *aux = aux_alloc(num_blocks);
	TEE_Result res = TEE_SUCCESS;
	size_t n = 0;
	size_t m = 0;
	size_t o = 0;

	if (!aux)
		return TEE_ERROR_OUT_OF_MEMORY;

	/*
	 * n is the number of block we're going to initialize/use.
	 * m is the offset from where we'll rewrite blocks and expect
	 * the changes to be visible until tee_fs_htree_close() is called
	 * without a call to tee_fs_htree_sync_to_storage() before.
	 * o is the number of blocks we're rewriting starting at m.
	 */
	for (n = 0; n < num_blocks; n += 3) {
		for (m = 0; m < n; m += 3) {
			for (o = 0; o < (n - m); o++) {
				res = htree_test_rewrite(aux, n, m, o);
				CHECK_RES(res, goto out);
				o += 2;
			}
		}
	}

out:
	aux_free(aux);
	return res;
}

static TEE_Result test_corrupt_type(const TEE_UUID *uuid, uint8_t *hash,
				    size_t num_blocks, struct test_aux *aux,
				    enum tee_fs_htree_type type, size_t idx)
{
	TEE_Result res = TEE_SUCCESS;
	struct test_aux aux2 = *aux;
	struct tee_fs_htree *ht = NULL;
	size_t offs = 0;
	size_t size = 0;
	size_t size0 = 0;
	size_t n = 0;

	res = test_get_offs_size(type, idx, 0, &offs, &size0);
	CHECK_RES(res, return res);

	aux2.data = malloc(aux->data_alloced);
	if (!aux2.data)
		return TEE_ERROR_OUT_OF_MEMORY;

	n = 0;
	while (true) {
		memcpy(aux2.data, aux->data, aux->data_len);

		res = test_get_offs_size(type, idx, 0, &offs, &size);
		CHECK_RES(res, goto out);
		aux2.data[offs + n]++;
		res = test_get_offs_size(type, idx, 1, &offs, &size);
		CHECK_RES(res, goto out);
		aux2.data[offs + n]++;

		/*
		 * Errors in head or node is detected by
		 * tee_fs_htree_open() errors in block is detected when
		 * actually read by do_range(read_block)
		 */
		res = tee_fs_htree_open(false, hash, 0, uuid, &test_htree_ops,
					&aux2, &ht);
		if (!res) {
			res = do_range(read_block, &ht, 0, num_blocks, 1);
			/*
			 * do_range(read_block,) is supposed to detect the
			 * error. If TEE_ERROR_TIME_NOT_SET is returned
			 * read_block() was acutally able to get some data,
			 * but the data was incorrect.
			 *
			 * If res == TEE_SUCCESS or
			 *    res == TEE_ERROR_TIME_NOT_SET
			 * there's some problem with the htree
			 * implementation.
			 */
			if (res == TEE_ERROR_TIME_NOT_SET) {
				EMSG("error: data silently corrupted");
				res = TEE_ERROR_SECURITY;
				goto out;
			}
			if (!res)
				break;
			tee_fs_htree_close(&ht);
		}

		/* We've tested the last byte, let's get out of here */
		if (n == size0 - 1)
			break;

		/* Increase n exponentionally after 1 to skip some testing */
		if (n)
			n += n;
		else
			n = 1;

		/* Make sure we test the last byte too */
		if (n >= size0)
			n = size0 - 1;
	}

	if (res) {
		res = TEE_SUCCESS;
	} else {
		EMSG("error: data corruption undetected");
		res = TEE_ERROR_SECURITY;
	}
out:
	free(aux2.data);
	tee_fs_htree_close(&ht);
	return res;
}



static TEE_Result test_corrupt(size_t num_blocks)
{
	struct ts_session *sess = ts_get_current_session();
	const TEE_UUID *uuid = &sess->ctx->uuid;
	TEE_Result res = TEE_SUCCESS;
	struct tee_fs_htree *ht = NULL;
	uint8_t hash[TEE_FS_HTREE_HASH_SIZE] = { 0 };
	struct test_aux *aux = NULL;
	size_t n = 0;

	aux = aux_alloc(num_blocks);
	if (!aux) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	aux->data_len = 0;
	memset(aux->data, 0xce, aux->data_alloced);

	/* Write the object and close it */
	res = tee_fs_htree_open(true, hash, 0, uuid, &test_htree_ops, aux, &ht);
	CHECK_RES(res, goto out);
	res = do_range(write_block, &ht, 0, num_blocks, 1);
	CHECK_RES(res, goto out);
	res = tee_fs_htree_sync_to_storage(&ht, hash, NULL);
	CHECK_RES(res, goto out);
	tee_fs_htree_close(&ht);

	/* Verify that the object can be read correctly */
	res = tee_fs_htree_open(false, hash, 0, uuid, &test_htree_ops, aux,
				&ht);
	CHECK_RES(res, goto out);
	res = do_range(read_block, &ht, 0, num_blocks, 1);
	CHECK_RES(res, goto out);
	tee_fs_htree_close(&ht);

	res = test_corrupt_type(uuid, hash, num_blocks, aux,
				TEE_FS_HTREE_TYPE_HEAD, 0);
	CHECK_RES(res, goto out);
	for (n = 0; n < num_blocks; n++) {
		res = test_corrupt_type(uuid, hash, num_blocks, aux,
					TEE_FS_HTREE_TYPE_NODE, n);
		CHECK_RES(res, goto out);
	}
	for (n = 0; n < num_blocks; n++) {
		res = test_corrupt_type(uuid, hash, num_blocks, aux,
					TEE_FS_HTREE_TYPE_BLOCK, n);
		CHECK_RES(res, goto out);
	}

out:
	tee_fs_htree_close(&ht);
	aux_free(aux);
	return res;
}

TEE_Result core_fs_htree_tests(uint32_t nParamTypes,
			       TEE_Param pParams[TEE_NUM_PARAMS] __unused)
{
	TEE_Result res = TEE_SUCCESS;

	if (nParamTypes)
		return TEE_ERROR_BAD_PARAMETERS;

	res = test_write_read(10);
	if (res)
		return res;

	return test_corrupt(5);
}
