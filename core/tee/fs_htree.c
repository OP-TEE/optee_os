// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2017, Linaro Limited
 */

#include <assert.h>
#include <crypto/crypto.h>
#include <initcall.h>
#include <kernel/tee_common_otp.h>
#include <stdlib.h>
#include <string_ext.h>
#include <string.h>
#include <tee/fs_htree.h>
#include <tee/tee_fs_key_manager.h>
#include <tee/tee_fs_rpc.h>
#include <utee_defines.h>
#include <util.h>

#define TEE_FS_HTREE_CHIP_ID_SIZE	32
#define TEE_FS_HTREE_HASH_ALG		TEE_ALG_SHA256
#define TEE_FS_HTREE_TSK_SIZE		TEE_FS_HTREE_HASH_SIZE
#define TEE_FS_HTREE_ENC_ALG		TEE_ALG_AES_ECB_NOPAD
#define TEE_FS_HTREE_ENC_SIZE		TEE_AES_BLOCK_SIZE
#define TEE_FS_HTREE_SSK_SIZE		TEE_FS_HTREE_HASH_SIZE

#define TEE_FS_HTREE_AUTH_ENC_ALG	TEE_ALG_AES_GCM
#define TEE_FS_HTREE_HMAC_ALG		TEE_ALG_HMAC_SHA256

#define BLOCK_NUM_TO_NODE_ID(num)	((num) + 1)

#define NODE_ID_TO_BLOCK_NUM(id)	((id) - 1)

/*
 * The hash tree is implemented as a binary tree with the purpose to ensure
 * integrity of the data in the nodes. The data in the nodes their turn
 * provides both integrity and confidentiality of the data blocks.
 *
 * The hash tree is saved in a file as:
 * +----------------------------+
 * | htree_image.0		|
 * | htree_image.1		|
 * +----------------------------+
 * | htree_node_image.1.0	|
 * | htree_node_image.1.1	|
 * +----------------------------+
 * | htree_node_image.2.0	|
 * | htree_node_image.2.1	|
 * +----------------------------+
 * | htree_node_image.3.0	|
 * | htree_node_image.3.1	|
 * +----------------------------+
 * | htree_node_image.4.0	|
 * | htree_node_image.4.1	|
 * +----------------------------+
 * ...
 *
 * htree_image is the header of the file, there's two instances of it. One
 * which is committed and the other is used when updating the file. Which
 * is committed is indicated by the "counter" field, the one with the
 * largest value is selected.
 *
 * htree_node_image is a node in the hash tree, each node has two instances
 * which is committed is decided by the parent node .flag bit
 * HTREE_NODE_COMMITTED_CHILD. Which version is the committed version of
 * node 1 is determined by the by the lowest bit of the counter field in
 * the header.
 *
 * Note that nodes start counting at 1 while blocks at 0, this means that
 * block 0 is represented by node 1.
 *
 * Where different elements are stored in the file is managed by the file
 * system.
 */

#define HTREE_NODE_COMMITTED_BLOCK	BIT32(0)
/* n is 0 or 1 */
#define HTREE_NODE_COMMITTED_CHILD(n)	BIT32(1 + (n))

struct htree_node {
	size_t id;
	bool dirty;
	bool block_updated;
	struct tee_fs_htree_node_image node;
	struct htree_node *parent;
	struct htree_node *child[2];
};

struct tee_fs_htree {
	struct htree_node root;
	struct tee_fs_htree_image head;
	uint8_t fek[TEE_FS_HTREE_FEK_SIZE];
	struct tee_fs_htree_imeta imeta;
	bool dirty;
	const TEE_UUID *uuid;
	const struct tee_fs_htree_storage *stor;
	void *stor_aux;
};

struct traverse_arg;
typedef TEE_Result (*traverse_cb_t)(struct traverse_arg *targ,
				    struct htree_node *node);
struct traverse_arg {
	struct tee_fs_htree *ht;
	traverse_cb_t cb;
	void *arg;
};

static TEE_Result rpc_read(struct tee_fs_htree *ht, enum tee_fs_htree_type type,
			   size_t idx, size_t vers, void *data, size_t dlen)
{
	TEE_Result res;
	struct tee_fs_rpc_operation op;
	size_t bytes;
	void *p;

	res = ht->stor->rpc_read_init(ht->stor_aux, &op, type, idx, vers, &p);
	if (res != TEE_SUCCESS)
		return res;

	res = ht->stor->rpc_read_final(&op, &bytes);
	if (res != TEE_SUCCESS)
		return res;

	if (bytes != dlen)
		return TEE_ERROR_CORRUPT_OBJECT;

	memcpy(data, p, dlen);
	return TEE_SUCCESS;
}

static TEE_Result rpc_read_head(struct tee_fs_htree *ht, size_t vers,
				struct tee_fs_htree_image *head)
{
	return rpc_read(ht, TEE_FS_HTREE_TYPE_HEAD, 0, vers,
			head, sizeof(*head));
}

static TEE_Result rpc_read_node(struct tee_fs_htree *ht, size_t node_id,
				size_t vers,
				struct tee_fs_htree_node_image *node)
{
	return rpc_read(ht, TEE_FS_HTREE_TYPE_NODE, node_id - 1, vers,
			node, sizeof(*node));
}

static TEE_Result rpc_write(struct tee_fs_htree *ht,
			    enum tee_fs_htree_type type, size_t idx,
			    size_t vers, const void *data, size_t dlen)
{
	TEE_Result res;
	struct tee_fs_rpc_operation op;
	void *p;

	res = ht->stor->rpc_write_init(ht->stor_aux, &op, type, idx, vers, &p);
	if (res != TEE_SUCCESS)
		return res;

	memcpy(p, data, dlen);
	return ht->stor->rpc_write_final(&op);
}

static TEE_Result rpc_write_head(struct tee_fs_htree *ht, size_t vers,
				 const struct tee_fs_htree_image *head)
{
	return rpc_write(ht, TEE_FS_HTREE_TYPE_HEAD, 0, vers,
			 head, sizeof(*head));
}

static TEE_Result rpc_write_node(struct tee_fs_htree *ht, size_t node_id,
				 size_t vers,
				 const struct tee_fs_htree_node_image *node)
{
	return rpc_write(ht, TEE_FS_HTREE_TYPE_NODE, node_id - 1, vers,
			 node, sizeof(*node));
}

static TEE_Result traverse_post_order(struct traverse_arg *targ,
				      struct htree_node *node)
{
	TEE_Result res;

	/*
	 * This function is recursing but not very deep, only with Log(N)
	 * maximum depth.
	 */

	if (!node)
		return TEE_SUCCESS;

	res = traverse_post_order(targ, node->child[0]);
	if (res != TEE_SUCCESS)
		return res;

	res = traverse_post_order(targ, node->child[1]);
	if (res != TEE_SUCCESS)
		return res;

	return targ->cb(targ, node);
}

static TEE_Result htree_traverse_post_order(struct tee_fs_htree *ht,
					    traverse_cb_t cb, void *arg)
{
	struct traverse_arg targ = { ht, cb, arg };

	return traverse_post_order(&targ, &ht->root);
}

static size_t node_id_to_level(size_t node_id)
{
	assert(node_id && node_id < UINT_MAX);
	/* Calculate level of the node, root node (1) has level 1 */
	return sizeof(unsigned int) * 8 - __builtin_clz(node_id);
}

static struct htree_node *find_closest_node(struct tee_fs_htree *ht,
					    size_t node_id)
{
	struct htree_node *node = &ht->root;
	size_t level = node_id_to_level(node_id);
	size_t n;

	/* n = 1 because root node is level 1 */
	for (n = 1; n < level; n++) {
		struct htree_node *child;
		size_t bit_idx;

		/*
		 * The difference between levels of the current node and
		 * the node we're looking for tells which bit decides
		 * direction in the tree.
		 *
		 * As the first bit has index 0 we'll subtract 1
		 */
		bit_idx = level - n - 1;
		child = node->child[((node_id >> bit_idx) & 1)];
		if (!child)
			return node;
		node = child;
	}

	return node;
}

static struct htree_node *find_node(struct tee_fs_htree *ht, size_t node_id)
{
	struct htree_node *node = find_closest_node(ht, node_id);

	if (node && node->id == node_id)
		return node;
	return NULL;
}

static TEE_Result get_node(struct tee_fs_htree *ht, bool create,
			   size_t node_id, struct htree_node **node_ret)
{
	struct htree_node *node;
	struct htree_node *nc;
	size_t n;

	node = find_closest_node(ht, node_id);
	if (!node)
		return TEE_ERROR_GENERIC;
	if (node->id == node_id)
		goto ret_node;

	/*
	 * Trying to read beyond end of file should be caught earlier than
	 * here.
	 */
	if (!create)
		return TEE_ERROR_GENERIC;

	/*
	 * Add missing nodes, some nodes may already be there. When we've
	 * processed the range all nodes up to node_id will be in the tree.
	 */
	for (n = node->id + 1; n <= node_id; n++) {
		node = find_closest_node(ht, n);
		if (node->id == n)
			continue;
		/* Node id n should be a child of node */
		assert((n >> 1) == node->id);
		assert(!node->child[n & 1]);

		nc = calloc(1, sizeof(*nc));
		if (!nc)
			return TEE_ERROR_OUT_OF_MEMORY;
		nc->id = n;
		nc->parent = node;
		node->child[n & 1] = nc;
		node = nc;
	}

	if (node->id > ht->imeta.max_node_id)
		ht->imeta.max_node_id = node->id;

ret_node:
	*node_ret = node;
	return TEE_SUCCESS;
}

static int get_idx_from_counter(uint32_t counter0, uint32_t counter1)
{
	if (!(counter0 & 1)) {
		if (!(counter1 & 1))
			return 0;
		if (counter0 > counter1)
			return 0;
		else
			return 1;
	}

	if (counter1 & 1)
		return 1;
	else
		return -1;
}

static TEE_Result init_head_from_data(struct tee_fs_htree *ht,
				      const uint8_t *hash, uint32_t min_counter)
{
	TEE_Result res;
	int idx;

	if (hash) {
		for (idx = 0;; idx++) {
			res = rpc_read_node(ht, 1, idx, &ht->root.node);
			if (res != TEE_SUCCESS)
				return res;

			if (!memcmp(ht->root.node.hash, hash,
				    sizeof(ht->root.node.hash))) {
				res = rpc_read_head(ht, idx, &ht->head);
				if (res != TEE_SUCCESS)
					return res;
				break;
			}

			if (idx)
				return TEE_ERROR_CORRUPT_OBJECT;
		}
	} else {
		struct tee_fs_htree_image head[2];

		for (idx = 0; idx < 2; idx++) {
			res = rpc_read_head(ht, idx, head + idx);
			if (res != TEE_SUCCESS)
				return res;
		}

		idx = get_idx_from_counter(head[0].counter, head[1].counter);
		if (idx < 0)
			return TEE_ERROR_SECURITY;

		res = rpc_read_node(ht, 1, idx, &ht->root.node);
		if (res != TEE_SUCCESS)
			return res;

		ht->head = head[idx];
	}

	if (ht->head.counter < min_counter)
		return TEE_ERROR_SECURITY;

	ht->root.id = 1;

	return TEE_SUCCESS;
}

static TEE_Result init_tree_from_data(struct tee_fs_htree *ht)
{
	TEE_Result res;
	struct tee_fs_htree_node_image node_image;
	struct htree_node *node;
	struct htree_node *nc;
	size_t committed_version;
	size_t node_id = 2;

	while (node_id <= ht->imeta.max_node_id) {
		node = find_node(ht, node_id >> 1);
		if (!node)
			return TEE_ERROR_GENERIC;
		committed_version = !!(node->node.flags &
				    HTREE_NODE_COMMITTED_CHILD(node_id & 1));

		res = rpc_read_node(ht, node_id, committed_version,
				    &node_image);
		if (res != TEE_SUCCESS)
			return res;

		res = get_node(ht, true, node_id, &nc);
		if (res != TEE_SUCCESS)
			return res;
		nc->node = node_image;
		node_id++;
	}

	return TEE_SUCCESS;
}

static TEE_Result calc_node_hash(struct htree_node *node,
				 struct tee_fs_htree_meta *meta, void *ctx,
				 uint8_t *digest)
{
	TEE_Result res;
	uint8_t *ndata = (uint8_t *)&node->node + sizeof(node->node.hash);
	size_t nsize = sizeof(node->node) - sizeof(node->node.hash);

	res = crypto_hash_init(ctx);
	if (res != TEE_SUCCESS)
		return res;

	res = crypto_hash_update(ctx, ndata, nsize);
	if (res != TEE_SUCCESS)
		return res;

	if (meta) {
		res = crypto_hash_update(ctx, (void *)meta, sizeof(*meta));
		if (res != TEE_SUCCESS)
			return res;
	}

	if (node->child[0]) {
		res = crypto_hash_update(ctx, node->child[0]->node.hash,
					 sizeof(node->child[0]->node.hash));
		if (res != TEE_SUCCESS)
			return res;
	}

	if (node->child[1]) {
		res = crypto_hash_update(ctx, node->child[1]->node.hash,
					 sizeof(node->child[1]->node.hash));
		if (res != TEE_SUCCESS)
			return res;
	}

	return crypto_hash_final(ctx, digest, TEE_FS_HTREE_HASH_SIZE);
}

static TEE_Result authenc_init(void **ctx_ret, TEE_OperationMode mode,
			       struct tee_fs_htree *ht,
			       struct tee_fs_htree_node_image *ni,
			       size_t payload_len)
{
	TEE_Result res = TEE_SUCCESS;
	const uint32_t alg = TEE_FS_HTREE_AUTH_ENC_ALG;
	void *ctx;
	size_t aad_len = TEE_FS_HTREE_FEK_SIZE + TEE_FS_HTREE_IV_SIZE;
	uint8_t *iv;

	if (ni) {
		iv = ni->iv;
	} else {
		iv = ht->head.iv;
		aad_len += TEE_FS_HTREE_HASH_SIZE + sizeof(ht->head.counter);
	}

	if (mode == TEE_MODE_ENCRYPT) {
		res = crypto_rng_read(iv, TEE_FS_HTREE_IV_SIZE);
		if (res != TEE_SUCCESS)
			return res;
	}

	res = crypto_authenc_alloc_ctx(&ctx, alg);
	if (res != TEE_SUCCESS)
		return res;

	res = crypto_authenc_init(ctx, mode, ht->fek, TEE_FS_HTREE_FEK_SIZE, iv,
				  TEE_FS_HTREE_IV_SIZE, TEE_FS_HTREE_TAG_SIZE,
				  aad_len, payload_len);
	if (res != TEE_SUCCESS)
		goto err_free;

	if (!ni) {
		res = crypto_authenc_update_aad(ctx, mode, ht->root.node.hash,
						TEE_FS_HTREE_FEK_SIZE);
		if (res != TEE_SUCCESS)
			goto err;

		res = crypto_authenc_update_aad(ctx, mode,
						(void *)&ht->head.counter,
						sizeof(ht->head.counter));
		if (res != TEE_SUCCESS)
			goto err;
	}

	res = crypto_authenc_update_aad(ctx, mode, ht->head.enc_fek,
					TEE_FS_HTREE_FEK_SIZE);
	if (res != TEE_SUCCESS)
		goto err;

	res = crypto_authenc_update_aad(ctx, mode, iv, TEE_FS_HTREE_IV_SIZE);
	if (res != TEE_SUCCESS)
		goto err;

	*ctx_ret = ctx;

	return TEE_SUCCESS;
err:
	crypto_authenc_final(ctx);
err_free:
	crypto_authenc_free_ctx(ctx);
	return res;
}

static TEE_Result authenc_decrypt_final(void *ctx, const uint8_t *tag,
					const void *crypt, size_t len,
					void *plain)
{
	TEE_Result res;
	size_t out_size = len;

	res = crypto_authenc_dec_final(ctx, crypt, len, plain, &out_size, tag,
				       TEE_FS_HTREE_TAG_SIZE);
	crypto_authenc_final(ctx);
	crypto_authenc_free_ctx(ctx);

	if (res == TEE_SUCCESS && out_size != len)
		return TEE_ERROR_GENERIC;
	if (res == TEE_ERROR_MAC_INVALID)
		return TEE_ERROR_CORRUPT_OBJECT;

	return res;
}

static TEE_Result authenc_encrypt_final(void *ctx, uint8_t *tag,
					const void *plain, size_t len,
					void *crypt)
{
	TEE_Result res;
	size_t out_size = len;
	size_t out_tag_size = TEE_FS_HTREE_TAG_SIZE;

	res = crypto_authenc_enc_final(ctx, plain, len, crypt, &out_size, tag,
				       &out_tag_size);
	crypto_authenc_final(ctx);
	crypto_authenc_free_ctx(ctx);

	if (res == TEE_SUCCESS &&
	    (out_size != len || out_tag_size != TEE_FS_HTREE_TAG_SIZE))
		return TEE_ERROR_GENERIC;

	return res;
}

static TEE_Result verify_root(struct tee_fs_htree *ht)
{
	TEE_Result res;
	void *ctx;

	res = tee_fs_fek_crypt(ht->uuid, TEE_MODE_DECRYPT, ht->head.enc_fek,
			       sizeof(ht->fek), ht->fek);
	if (res != TEE_SUCCESS)
		return res;

	res = authenc_init(&ctx, TEE_MODE_DECRYPT, ht, NULL, sizeof(ht->imeta));
	if (res != TEE_SUCCESS)
		return res;

	return authenc_decrypt_final(ctx, ht->head.tag, ht->head.imeta,
				     sizeof(ht->imeta), &ht->imeta);
}

static TEE_Result verify_node(struct traverse_arg *targ,
			      struct htree_node *node)
{
	void *ctx = targ->arg;
	TEE_Result res;
	uint8_t digest[TEE_FS_HTREE_HASH_SIZE];

	if (node->parent)
		res = calc_node_hash(node, NULL, ctx, digest);
	else
		res = calc_node_hash(node, &targ->ht->imeta.meta, ctx, digest);
	if (res == TEE_SUCCESS &&
	    consttime_memcmp(digest, node->node.hash, sizeof(digest)))
		return TEE_ERROR_CORRUPT_OBJECT;

	return res;
}

static TEE_Result verify_tree(struct tee_fs_htree *ht)
{
	TEE_Result res;
	void *ctx;

	res = crypto_hash_alloc_ctx(&ctx, TEE_FS_HTREE_HASH_ALG);
	if (res != TEE_SUCCESS)
		return res;

	res = htree_traverse_post_order(ht, verify_node, ctx);
	crypto_hash_free_ctx(ctx);

	return res;
}

static TEE_Result init_root_node(struct tee_fs_htree *ht)
{
	TEE_Result res;
	void *ctx;

	res = crypto_hash_alloc_ctx(&ctx, TEE_FS_HTREE_HASH_ALG);
	if (res != TEE_SUCCESS)
		return res;

	ht->root.id = 1;
	ht->root.dirty = true;

	res = calc_node_hash(&ht->root, &ht->imeta.meta, ctx,
			     ht->root.node.hash);
	crypto_hash_free_ctx(ctx);

	return res;
}

TEE_Result tee_fs_htree_open(bool create, uint8_t *hash, uint32_t min_counter,
			     const TEE_UUID *uuid,
			     const struct tee_fs_htree_storage *stor,
			     void *stor_aux, struct tee_fs_htree **ht_ret)
{
	TEE_Result res;
	struct tee_fs_htree *ht = calloc(1, sizeof(*ht));

	if (!ht)
		return TEE_ERROR_OUT_OF_MEMORY;

	ht->uuid = uuid;
	ht->stor = stor;
	ht->stor_aux = stor_aux;

	if (create) {
		const struct tee_fs_htree_image dummy_head = {
			.counter = min_counter,
		};

		res = crypto_rng_read(ht->fek, sizeof(ht->fek));
		if (res != TEE_SUCCESS)
			goto out;

		res = tee_fs_fek_crypt(ht->uuid, TEE_MODE_ENCRYPT, ht->fek,
				       sizeof(ht->fek), ht->head.enc_fek);
		if (res != TEE_SUCCESS)
			goto out;

		res = init_root_node(ht);
		if (res != TEE_SUCCESS)
			goto out;

		ht->dirty = true;
		res = tee_fs_htree_sync_to_storage(&ht, hash, NULL);
		if (res != TEE_SUCCESS)
			goto out;
		res = rpc_write_head(ht, 0, &dummy_head);
	} else {
		res = init_head_from_data(ht, hash, min_counter);
		if (res != TEE_SUCCESS)
			goto out;

		res = verify_root(ht);
		if (res != TEE_SUCCESS)
			goto out;

		res = init_tree_from_data(ht);
		if (res != TEE_SUCCESS)
			goto out;

		res = verify_tree(ht);
	}
out:
	if (res == TEE_SUCCESS)
		*ht_ret = ht;
	else
		tee_fs_htree_close(&ht);
	return res;
}

struct tee_fs_htree_meta *tee_fs_htree_get_meta(struct tee_fs_htree *ht)
{
	return &ht->imeta.meta;
}

void tee_fs_htree_meta_set_dirty(struct tee_fs_htree *ht)
{
	ht->dirty = true;
	ht->root.dirty = true;
}

static TEE_Result free_node(struct traverse_arg *targ __unused,
			    struct htree_node *node)
{
	if (node->parent)
		free(node);
	return TEE_SUCCESS;
}

void tee_fs_htree_close(struct tee_fs_htree **ht)
{
	if (!*ht)
		return;
	htree_traverse_post_order(*ht, free_node, NULL);
	free(*ht);
	*ht = NULL;
}

static TEE_Result htree_sync_node_to_storage(struct traverse_arg *targ,
					     struct htree_node *node)
{
	TEE_Result res;
	uint8_t vers;
	struct tee_fs_htree_meta *meta = NULL;

	/*
	 * The node can be dirty while the block isn't updated due to
	 * updated children, but if block is updated the node has to be
	 * dirty.
	 */
	assert(node->dirty >= node->block_updated);

	if (!node->dirty)
		return TEE_SUCCESS;

	if (node->parent) {
		uint32_t f = HTREE_NODE_COMMITTED_CHILD(node->id & 1);

		node->parent->dirty = true;
		node->parent->node.flags ^= f;
		vers = !!(node->parent->node.flags & f);
	} else {
		/*
		 * Counter isn't updated yet, it's increased just before
		 * writing the header.
		 */
		vers = !(targ->ht->head.counter & 1);
		meta = &targ->ht->imeta.meta;
	}

	res = calc_node_hash(node, meta, targ->arg, node->node.hash);
	if (res != TEE_SUCCESS)
		return res;

	node->dirty = false;
	node->block_updated = false;

	return rpc_write_node(targ->ht, node->id, vers, &node->node);
}

static TEE_Result update_root(struct tee_fs_htree *ht)
{
	TEE_Result res;
	void *ctx;

	ht->head.counter++;

	res = authenc_init(&ctx, TEE_MODE_ENCRYPT, ht, NULL, sizeof(ht->imeta));
	if (res != TEE_SUCCESS)
		return res;

	return authenc_encrypt_final(ctx, ht->head.tag, &ht->imeta,
				     sizeof(ht->imeta), &ht->head.imeta);
}

TEE_Result tee_fs_htree_sync_to_storage(struct tee_fs_htree **ht_arg,
					uint8_t *hash, uint32_t *counter)
{
	TEE_Result res;
	struct tee_fs_htree *ht = *ht_arg;
	void *ctx;

	if (!ht)
		return TEE_ERROR_CORRUPT_OBJECT;

	if (!ht->dirty)
		return TEE_SUCCESS;

	res = crypto_hash_alloc_ctx(&ctx, TEE_FS_HTREE_HASH_ALG);
	if (res != TEE_SUCCESS)
		return res;

	res = htree_traverse_post_order(ht, htree_sync_node_to_storage, ctx);
	if (res != TEE_SUCCESS)
		goto out;

	/* All the nodes are written to storage now. Time to update root. */
	res = update_root(ht);
	if (res != TEE_SUCCESS)
		goto out;

	res = rpc_write_head(ht, ht->head.counter & 1, &ht->head);
	if (res != TEE_SUCCESS)
		goto out;

	ht->dirty = false;
	if (hash)
		memcpy(hash, ht->root.node.hash, sizeof(ht->root.node.hash));
	if (counter)
		*counter = ht->head.counter;
out:
	crypto_hash_free_ctx(ctx);
	if (res != TEE_SUCCESS)
		tee_fs_htree_close(ht_arg);
	return res;
}

static TEE_Result get_block_node(struct tee_fs_htree *ht, bool create,
				 size_t block_num, struct htree_node **node)
{
	TEE_Result res;
	struct htree_node *nd;

	res = get_node(ht, create, BLOCK_NUM_TO_NODE_ID(block_num), &nd);
	if (res == TEE_SUCCESS)
		*node = nd;

	return res;
}

TEE_Result tee_fs_htree_write_block(struct tee_fs_htree **ht_arg,
				    size_t block_num, const void *block)
{
	struct tee_fs_htree *ht = *ht_arg;
	TEE_Result res;
	struct tee_fs_rpc_operation op;
	struct htree_node *node = NULL;
	uint8_t block_vers;
	void *ctx;
	void *enc_block;

	if (!ht)
		return TEE_ERROR_CORRUPT_OBJECT;

	res = get_block_node(ht, true, block_num, &node);
	if (res != TEE_SUCCESS)
		goto out;

	if (!node->block_updated)
		node->node.flags ^= HTREE_NODE_COMMITTED_BLOCK;

	block_vers = !!(node->node.flags & HTREE_NODE_COMMITTED_BLOCK);
	res = ht->stor->rpc_write_init(ht->stor_aux, &op,
				       TEE_FS_HTREE_TYPE_BLOCK, block_num,
				       block_vers, &enc_block);
	if (res != TEE_SUCCESS)
		goto out;

	res = authenc_init(&ctx, TEE_MODE_ENCRYPT, ht, &node->node,
			   ht->stor->block_size);
	if (res != TEE_SUCCESS)
		goto out;
	res = authenc_encrypt_final(ctx, node->node.tag, block,
				    ht->stor->block_size, enc_block);
	if (res != TEE_SUCCESS)
		goto out;

	res = ht->stor->rpc_write_final(&op);
	if (res != TEE_SUCCESS)
		goto out;

	node->block_updated = true;
	node->dirty = true;
	ht->dirty = true;
out:
	if (res != TEE_SUCCESS)
		tee_fs_htree_close(ht_arg);
	return res;
}

TEE_Result tee_fs_htree_read_block(struct tee_fs_htree **ht_arg,
				   size_t block_num, void *block)
{
	struct tee_fs_htree *ht = *ht_arg;
	TEE_Result res;
	struct tee_fs_rpc_operation op;
	struct htree_node *node;
	uint8_t block_vers;
	size_t len;
	void *ctx;
	void *enc_block;

	if (!ht)
		return TEE_ERROR_CORRUPT_OBJECT;

	res = get_block_node(ht, false, block_num, &node);
	if (res != TEE_SUCCESS)
		goto out;

	block_vers = !!(node->node.flags & HTREE_NODE_COMMITTED_BLOCK);
	res = ht->stor->rpc_read_init(ht->stor_aux, &op,
				      TEE_FS_HTREE_TYPE_BLOCK, block_num,
				      block_vers, &enc_block);
	if (res != TEE_SUCCESS)
		goto out;

	res = ht->stor->rpc_read_final(&op, &len);
	if (res != TEE_SUCCESS)
		goto out;
	if (len != ht->stor->block_size) {
		res = TEE_ERROR_CORRUPT_OBJECT;
		goto out;
	}

	res = authenc_init(&ctx, TEE_MODE_DECRYPT, ht, &node->node,
			   ht->stor->block_size);
	if (res != TEE_SUCCESS)
		goto out;

	res = authenc_decrypt_final(ctx, node->node.tag, enc_block,
				    ht->stor->block_size, block);
out:
	if (res != TEE_SUCCESS)
		tee_fs_htree_close(ht_arg);
	return res;
}

TEE_Result tee_fs_htree_truncate(struct tee_fs_htree **ht_arg, size_t block_num)
{
	struct tee_fs_htree *ht = *ht_arg;
	size_t node_id = BLOCK_NUM_TO_NODE_ID(block_num);
	struct htree_node *node;

	if (!ht)
		return TEE_ERROR_CORRUPT_OBJECT;

	while (node_id < ht->imeta.max_node_id) {
		node = find_closest_node(ht, ht->imeta.max_node_id);
		assert(node && node->id == ht->imeta.max_node_id);
		assert(!node->child[0] && !node->child[1]);
		assert(node->parent);
		assert(node->parent->child[node->id & 1] == node);
		node->parent->child[node->id & 1] = NULL;
		free(node);
		ht->imeta.max_node_id--;
		ht->dirty = true;
	}

	return TEE_SUCCESS;
}
