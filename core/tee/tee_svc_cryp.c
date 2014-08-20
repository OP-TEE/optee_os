/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#include <tee_api_types.h>
#include <kernel/tee_ta_manager.h>
#include <utee_defines.h>
#include <mm/tee_mmu.h>
#include <tee/tee_svc.h>
#include <tee/tee_svc_cryp.h>
#include <sys/queue.h>
#include <tee/tee_obj.h>
#include <tee/tee_cryp_provider.h>
#include <kernel/tee_core_trace.h>
#include <rng_support.h>

/* Set an attribute on an object */
#define SET_ATTRIBUTE(_object, _props, _attr)	\
	(_object)->have_attrs |= \
		(1 << (tee_svc_cryp_obj_find_type_attr_idx((_attr), (_props))))

/* Get an attribute on an object */
#define GET_ATTRIBUTE(_object, _props, _attr)	\
	((_object)->have_attrs & \
		(1 << (tee_svc_cryp_obj_find_type_attr_idx((_attr), (_props)))))

#define TEE_USAGE_DEFAULT   0xffffffff
#define TEE_ATTR_BIT_PROTECTED              (1 << 28)

typedef void (*tee_cryp_ctx_finalize_func_t) (void *ctx, uint32_t algo);
struct tee_cryp_state {
	TAILQ_ENTRY(tee_cryp_state) link;
	uint32_t algo;
	uint32_t mode;
	uint32_t key1;
	uint32_t key2;
	size_t ctx_size;
	void *ctx;
	tee_cryp_ctx_finalize_func_t ctx_finalize;
};

struct tee_cryp_obj_secret {
	uint32_t key_size;

	/*
	 * Pseudo code visualize layout of structure
	 * Next follows data, such as:
	 *	uint8_t data[key_size]
	 * key_size must never exceed
	 * (obj->data_size - sizeof(struct tee_cryp_obj_secret)).
	 */
};

#define TEE_TYPE_ATTR_OPTIONAL       0x0
#define TEE_TYPE_ATTR_REQUIRED       0x1
#define TEE_TYPE_ATTR_OPTIONAL_GROUP 0x2
#define TEE_TYPE_ATTR_SIZE_INDICATOR 0x4
#define TEE_TYPE_ATTR_GEN_KEY_OPT    0x8
#define TEE_TYPE_ATTR_GEN_KEY_REQ    0x10

#define TEE_TYPE_CONV_FUNC_NONE       0
    /* Handle storing of generic secret keys of varying lengths */
#define TEE_TYPE_CONV_FUNC_SECRET     1
    /* Convert to/from big-endian byte array and provider-specific bignum */
#define TEE_TYPE_CONV_FUNC_BIGNUM     2
    /* Convert to/from value attribute depending on direction */
#define TEE_TYPE_CONV_FUNC_VALUE      4

struct tee_cryp_obj_type_attrs {
	uint32_t attr_id;
	uint16_t flags;
	uint16_t conv_func;
	uint16_t raw_offs;
	uint16_t raw_size;
};

#define RAW_DATA(_x, _y)	\
	.raw_offs = offsetof(_x, _y), .raw_size = TEE_MEMBER_SIZE(_x, _y)

static const struct tee_cryp_obj_type_attrs
	tee_cryp_obj_secret_value_attrs[] = {
	{
	.attr_id = TEE_ATTR_SECRET_VALUE,
	.flags = TEE_TYPE_ATTR_REQUIRED | TEE_TYPE_ATTR_SIZE_INDICATOR,
	.conv_func = TEE_TYPE_CONV_FUNC_SECRET,
	.raw_offs = 0,
	.raw_size = 0
	},
};

static const struct tee_cryp_obj_type_attrs tee_cryp_obj_rsa_pub_key_attrs[] = {
	{
	.attr_id = TEE_ATTR_RSA_MODULUS,
	.flags = TEE_TYPE_ATTR_REQUIRED | TEE_TYPE_ATTR_SIZE_INDICATOR,
	.conv_func = TEE_TYPE_CONV_FUNC_BIGNUM,
	RAW_DATA(struct rsa_public_key_s, N)
	},

	{
	.attr_id = TEE_ATTR_RSA_PUBLIC_EXPONENT,
	.flags = TEE_TYPE_ATTR_REQUIRED,
	.conv_func = TEE_TYPE_CONV_FUNC_BIGNUM,
	RAW_DATA(struct rsa_public_key_s, e)
	},
};

static const struct tee_cryp_obj_type_attrs tee_cryp_obj_rsa_keypair_attrs[] = {
	{
	.attr_id = TEE_ATTR_RSA_MODULUS,
	.flags = TEE_TYPE_ATTR_REQUIRED | TEE_TYPE_ATTR_SIZE_INDICATOR,
	.conv_func = TEE_TYPE_CONV_FUNC_BIGNUM,
	RAW_DATA(struct rsa_keypair_s, N)
	},

	{
	.attr_id = TEE_ATTR_RSA_PUBLIC_EXPONENT,
	.flags = TEE_TYPE_ATTR_REQUIRED,
	.conv_func = TEE_TYPE_CONV_FUNC_BIGNUM,
	RAW_DATA(struct rsa_keypair_s, e)
	},

	{
	.attr_id = TEE_ATTR_RSA_PRIVATE_EXPONENT,
	.flags = TEE_TYPE_ATTR_REQUIRED,
	.conv_func = TEE_TYPE_CONV_FUNC_BIGNUM,
	RAW_DATA(struct rsa_keypair_s, d)
	},

	{
	.attr_id = TEE_ATTR_RSA_PRIME1,
	.flags = TEE_TYPE_ATTR_OPTIONAL_GROUP,
	.conv_func = TEE_TYPE_CONV_FUNC_BIGNUM,
	RAW_DATA(struct rsa_keypair_s, p)
	},

	{
	.attr_id = TEE_ATTR_RSA_PRIME2,
	.flags = TEE_TYPE_ATTR_OPTIONAL_GROUP,
	.conv_func = TEE_TYPE_CONV_FUNC_BIGNUM,
	RAW_DATA(struct rsa_keypair_s, q)
	},

	{
	.attr_id = TEE_ATTR_RSA_EXPONENT1,
	.flags = TEE_TYPE_ATTR_OPTIONAL_GROUP,
	.conv_func = TEE_TYPE_CONV_FUNC_BIGNUM,
	RAW_DATA(struct rsa_keypair_s, dP)
	},

	{
	.attr_id = TEE_ATTR_RSA_EXPONENT2,
	.flags = TEE_TYPE_ATTR_OPTIONAL_GROUP,
	.conv_func = TEE_TYPE_CONV_FUNC_BIGNUM,
	RAW_DATA(struct rsa_keypair_s, dQ)
	},

	{
	.attr_id = TEE_ATTR_RSA_COEFFICIENT,
	.flags = TEE_TYPE_ATTR_OPTIONAL_GROUP,
	.conv_func = TEE_TYPE_CONV_FUNC_BIGNUM,
	RAW_DATA(struct rsa_keypair_s, qP)
	},
};

static const struct tee_cryp_obj_type_attrs tee_cryp_obj_dsa_pub_key_attrs[] = {
	{
	.attr_id = TEE_ATTR_DSA_PRIME,
	.flags = TEE_TYPE_ATTR_REQUIRED,
	.conv_func = TEE_TYPE_CONV_FUNC_BIGNUM,
	RAW_DATA(struct dsa_public_key_s, p)
	},

	{
	.attr_id = TEE_ATTR_DSA_SUBPRIME,
	.flags = TEE_TYPE_ATTR_REQUIRED | TEE_TYPE_ATTR_SIZE_INDICATOR,
	.conv_func = TEE_TYPE_CONV_FUNC_BIGNUM,
	RAW_DATA(struct dsa_public_key_s, q)
	},

	{
	.attr_id = TEE_ATTR_DSA_BASE,
	.flags = TEE_TYPE_ATTR_REQUIRED,
	.conv_func = TEE_TYPE_CONV_FUNC_BIGNUM,
	RAW_DATA(struct dsa_public_key_s, g)
	},

	{
	.attr_id = TEE_ATTR_DSA_PUBLIC_VALUE,
	.flags = TEE_TYPE_ATTR_REQUIRED,
	.conv_func = TEE_TYPE_CONV_FUNC_BIGNUM,
	RAW_DATA(struct dsa_public_key_s, y)
	},
};

static const struct tee_cryp_obj_type_attrs tee_cryp_obj_dsa_keypair_attrs[] = {
	{
	.attr_id = TEE_ATTR_DSA_PRIME,
	.flags = TEE_TYPE_ATTR_REQUIRED | TEE_TYPE_ATTR_GEN_KEY_REQ,
	.conv_func = TEE_TYPE_CONV_FUNC_BIGNUM,
	RAW_DATA(struct dsa_keypair_s, p)
	},

	{
	.attr_id = TEE_ATTR_DSA_SUBPRIME,
	.flags = TEE_TYPE_ATTR_REQUIRED | TEE_TYPE_ATTR_SIZE_INDICATOR |
		 TEE_TYPE_ATTR_GEN_KEY_REQ,
	.conv_func = TEE_TYPE_CONV_FUNC_BIGNUM,
	RAW_DATA(struct dsa_keypair_s, q)
	},

	{
	.attr_id = TEE_ATTR_DSA_BASE,
	.flags = TEE_TYPE_ATTR_REQUIRED | TEE_TYPE_ATTR_GEN_KEY_REQ,
	.conv_func = TEE_TYPE_CONV_FUNC_BIGNUM,
	RAW_DATA(struct dsa_keypair_s, g)
	},

	{
	.attr_id = TEE_ATTR_DSA_PRIVATE_VALUE,
	.flags = TEE_TYPE_ATTR_REQUIRED,
	.conv_func = TEE_TYPE_CONV_FUNC_BIGNUM,
	RAW_DATA(struct dsa_keypair_s, x)
	},

	{
	.attr_id = TEE_ATTR_DSA_PUBLIC_VALUE,
	.flags = TEE_TYPE_ATTR_REQUIRED,
	.conv_func = TEE_TYPE_CONV_FUNC_BIGNUM,
	RAW_DATA(struct dsa_keypair_s, y)
	},
};

static const struct tee_cryp_obj_type_attrs tee_cryp_obj_dh_keypair_attrs[] = {
	{
	.attr_id = TEE_ATTR_DH_PRIME,
	.flags = TEE_TYPE_ATTR_REQUIRED | TEE_TYPE_ATTR_SIZE_INDICATOR |
		 TEE_TYPE_ATTR_GEN_KEY_REQ,
	.conv_func = TEE_TYPE_CONV_FUNC_BIGNUM,
	RAW_DATA(struct dh_keypair_s, p)
	},

	{
	.attr_id = TEE_ATTR_DH_BASE,
	.flags = TEE_TYPE_ATTR_REQUIRED | TEE_TYPE_ATTR_GEN_KEY_REQ,
	.conv_func = TEE_TYPE_CONV_FUNC_BIGNUM,
	RAW_DATA(struct dh_keypair_s, g)
	},

	{
	.attr_id = TEE_ATTR_DH_PUBLIC_VALUE,
	.flags = TEE_TYPE_ATTR_REQUIRED,
	.conv_func = TEE_TYPE_CONV_FUNC_BIGNUM,
	RAW_DATA(struct dh_keypair_s, y)
	},

	{
	.attr_id = TEE_ATTR_DH_PRIVATE_VALUE,
	.flags = TEE_TYPE_ATTR_REQUIRED,
	.conv_func = TEE_TYPE_CONV_FUNC_BIGNUM,
	RAW_DATA(struct dh_keypair_s, x)
	},

	{
	.attr_id = TEE_ATTR_DH_SUBPRIME,
	.flags = TEE_TYPE_ATTR_OPTIONAL_GROUP |	 TEE_TYPE_ATTR_GEN_KEY_OPT,
	.conv_func = TEE_TYPE_CONV_FUNC_BIGNUM,
	RAW_DATA(struct dh_keypair_s, q)
	},

	{
	.attr_id = TEE_ATTR_DH_X_BITS,
	.flags = TEE_TYPE_ATTR_GEN_KEY_OPT,
	.conv_func = TEE_TYPE_CONV_FUNC_VALUE,
	RAW_DATA(struct dh_keypair_s, xbits)
	},
};

struct tee_cryp_obj_type_props {
	TEE_ObjectType obj_type;
	uint16_t min_size;	/* may not be smaller than this */
	uint16_t max_size;	/* may not be larger than this */
	uint16_t alloc_size;	/* this many bytes are allocated to hold data */
	uint8_t quanta;		/* may only be an multiple of this */

	uint8_t num_type_attrs;
	const struct tee_cryp_obj_type_attrs *type_attrs;
};

#define PROP(obj_type, quanta, min_size, max_size, alloc_size, type_attrs) \
		{ (obj_type), (min_size), (max_size), (alloc_size), (quanta), \
		  TEE_ARRAY_SIZE(type_attrs), (type_attrs) }

static const struct tee_cryp_obj_type_props tee_cryp_obj_props[] = {
	PROP(TEE_TYPE_AES, 64, 128, 256,	/* valid sizes 128, 192, 256 */
		256 / 8 + sizeof(struct tee_cryp_obj_secret),
		tee_cryp_obj_secret_value_attrs),
	PROP(TEE_TYPE_DES, 56, 56, 56,
		/*
		* Valid size 56 without parity, note that we still allocate
		* for 64 bits since the key is supplied with parity.
		*/
		64 / 8 + sizeof(struct tee_cryp_obj_secret),
		tee_cryp_obj_secret_value_attrs),
	PROP(TEE_TYPE_DES3, 56, 112, 168,
		/*
		* Valid sizes 112, 168 without parity, note that we still
		* allocate for with space for the parity since the key is
		* supplied with parity.
		*/
		192 / 8 + sizeof(struct tee_cryp_obj_secret),
		tee_cryp_obj_secret_value_attrs),
	PROP(TEE_TYPE_HMAC_MD5, 8, 64, 512,
		512 / 8 + sizeof(struct tee_cryp_obj_secret),
		tee_cryp_obj_secret_value_attrs),
	PROP(TEE_TYPE_HMAC_SHA1, 8, 80, 512,
		512 / 8 + sizeof(struct tee_cryp_obj_secret),
		tee_cryp_obj_secret_value_attrs),
	PROP(TEE_TYPE_HMAC_SHA224, 8, 112, 512,
		512 / 8 + sizeof(struct tee_cryp_obj_secret),
		tee_cryp_obj_secret_value_attrs),
	PROP(TEE_TYPE_HMAC_SHA256, 8, 192, 1024,
		1024 / 8 + sizeof(struct tee_cryp_obj_secret),
		tee_cryp_obj_secret_value_attrs),
	PROP(TEE_TYPE_HMAC_SHA384, 8, 256, 1024,
		1024 / 8 + sizeof(struct tee_cryp_obj_secret),
		tee_cryp_obj_secret_value_attrs),
	PROP(TEE_TYPE_HMAC_SHA512, 8, 256, 1024,
		1024 / 8 + sizeof(struct tee_cryp_obj_secret),
		tee_cryp_obj_secret_value_attrs),
	PROP(TEE_TYPE_GENERIC_SECRET, 8, 0, 4096,
		4096 / 8 + sizeof(struct tee_cryp_obj_secret),
		tee_cryp_obj_secret_value_attrs),

	PROP(TEE_TYPE_RSA_PUBLIC_KEY, 1, 256, 2048,
		sizeof(struct rsa_public_key_s),
		tee_cryp_obj_rsa_pub_key_attrs),

	PROP(TEE_TYPE_RSA_KEYPAIR, 1, 256, 2048,
		sizeof(struct rsa_keypair_s),
		tee_cryp_obj_rsa_keypair_attrs),

	PROP(TEE_TYPE_DSA_PUBLIC_KEY, 64, 512, 1024,
		sizeof(struct dsa_public_key_s),
		tee_cryp_obj_dsa_pub_key_attrs),

	PROP(TEE_TYPE_DSA_KEYPAIR, 64, 512, 1024,
		sizeof(struct dsa_keypair_s),
		tee_cryp_obj_dsa_keypair_attrs),

	PROP(TEE_TYPE_DH_KEYPAIR, 1, 256, 2048,
		sizeof(struct dh_keypair_s),
		tee_cryp_obj_dh_keypair_attrs),
};

TEE_Result tee_svc_cryp_obj_get_info(uint32_t obj, TEE_ObjectInfo *info)
{
	TEE_Result res;
	struct tee_ta_session *sess;
	struct tee_obj *o;

	res = tee_ta_get_current_session(&sess);
	if (res != TEE_SUCCESS)
		return res;

	res = tee_obj_get(sess->ctx, obj, &o);
	if (res != TEE_SUCCESS)
		return res;

	return tee_svc_copy_to_user(sess, info, &o->info, sizeof(o->info));
}

TEE_Result tee_svc_cryp_obj_restrict_usage(uint32_t obj, uint32_t usage)
{
	TEE_Result res;
	struct tee_ta_session *sess;
	struct tee_obj *o;

	res = tee_ta_get_current_session(&sess);
	if (res != TEE_SUCCESS)
		return res;

	res = tee_obj_get(sess->ctx, obj, &o);
	if (res != TEE_SUCCESS)
		return res;

	o->info.objectUsage &= usage;

	return TEE_SUCCESS;
}

static TEE_Result tee_svc_cryp_obj_get_raw_data(
		struct tee_obj *o,
		const struct tee_cryp_obj_type_props *type_props,
		size_t idx, void **data, size_t *size)
{
	const struct tee_cryp_obj_type_attrs *type_attr =
	    type_props->type_attrs + idx;
	if (type_attr->raw_size == 0) {
		struct tee_cryp_obj_secret *key =
		    (struct tee_cryp_obj_secret *)o->data;

		/* Handle generic secret */
		if (type_attr->raw_offs != 0)
			return TEE_ERROR_BAD_STATE;
		*size = key->key_size;
	} else {
		*size = type_attr->raw_size;
	}
	*data = (uint8_t *)o->data + type_attr->raw_offs;
	return TEE_SUCCESS;
}

static int tee_svc_cryp_obj_find_type_attr_idx(
		uint32_t attr_id,
		const struct tee_cryp_obj_type_props *type_props)
{
	size_t n;

	for (n = 0; n < type_props->num_type_attrs; n++) {
		if (attr_id == type_props->type_attrs[n].attr_id)
			return n;
	}
	return -1;
}

static const struct tee_cryp_obj_type_props *tee_svc_find_type_props(
		TEE_ObjectType obj_type)
{
	size_t n;

	for (n = 0; n < TEE_ARRAY_SIZE(tee_cryp_obj_props); n++) {
		if (tee_cryp_obj_props[n].obj_type == obj_type)
			return tee_cryp_obj_props + n;
	}

	return NULL;
}

static TEE_Result tee_svc_cryp_obj_copy_out(struct tee_ta_session *sess,
					    void *buffer, size_t *size,
					    uint16_t conv_func,
					    void *raw_data,
					    size_t raw_data_size)
{
	TEE_Result res;
	size_t s;

	res = tee_svc_copy_from_user(sess, &s, size, sizeof(size_t));
	if (res != TEE_SUCCESS)
		return res;

	switch (conv_func) {
	case TEE_TYPE_CONV_FUNC_NONE:
		res =
		    tee_svc_copy_to_user(sess, size, &raw_data_size,
					 sizeof(size_t));
		if (res != TEE_SUCCESS)
			return res;

		if (s < raw_data_size)
			return TEE_ERROR_SHORT_BUFFER;

		return tee_svc_copy_to_user(sess, buffer, raw_data,
					    raw_data_size);
	case TEE_TYPE_CONV_FUNC_SECRET:
		{
			struct tee_cryp_obj_secret *obj;
			size_t key_size;

			if (!TEE_ALIGNMENT_IS_OK
			    (raw_data, struct tee_cryp_obj_secret))
				 return TEE_ERROR_BAD_STATE;
			obj = (struct tee_cryp_obj_secret *)(void *)raw_data;
			key_size = obj->key_size;

			res =
			    tee_svc_copy_to_user(sess, size, &key_size,
						 sizeof(size_t));
			if (res != TEE_SUCCESS)
				return res;

			if (s < key_size)
				return TEE_ERROR_SHORT_BUFFER;

			return tee_svc_copy_to_user(sess, buffer, obj + 1,
						    key_size);
		}

	case TEE_TYPE_CONV_FUNC_BIGNUM:
	{
		size_t req_size;
		bignum *bn = *(bignum **)raw_data;
		req_size = crypto_ops.bignum.bin_size_for(bn);
		if (req_size == 0)
			return TEE_SUCCESS;
		res = tee_svc_copy_to_user(
			sess, size, &req_size, sizeof(size_t));
		if (res != TEE_SUCCESS)
			return res;

		/* Check that the converted result fits the user buffer. */
		if (s < req_size)
			return TEE_ERROR_SHORT_BUFFER;

		/* Check we can access data using supplied user mode pointer */
		res = tee_mmu_check_access_rights(sess->ctx,
						  TEE_MEMORY_ACCESS_READ |
						  TEE_MEMORY_ACCESS_WRITE |
						  TEE_MEMORY_ACCESS_ANY_OWNER,
						  (tee_uaddr_t)buffer,
						  req_size);
		if (res != TEE_SUCCESS)
			return res;

		/*
		 * Write the bignum (wich raw data points to) into an array of
		 * bytes (stored in buffer)
		 */
		crypto_ops.bignum.bn2bin(bn, buffer);
		return TEE_SUCCESS;
	}

	case TEE_TYPE_CONV_FUNC_VALUE:
		{
			uint32_t value[2] = { 0, 0 };
			size_t n = sizeof(value);

			/*
			 * a value attribute consists of two uint32 but have not
			 * seen anything that actaully would need that so this
			 * fills in one with data and the other with zero
			 */
			TEE_ASSERT(raw_data_size == sizeof(uint32_t));
			value[0] = *(uint32_t *)raw_data;

			res =
			    tee_svc_copy_to_user(sess, size, &n,
						 sizeof(size_t));
			if (res != TEE_SUCCESS)
				return res;

			/* Check that the converted result fits the user buf */
			if (s < n)
				return TEE_ERROR_SHORT_BUFFER;

			return tee_svc_copy_to_user(sess, buffer, &value, n);
		}
	default:
		return TEE_ERROR_BAD_STATE;
	}

}

TEE_Result tee_svc_cryp_obj_get_attr(uint32_t obj, uint32_t attr_id,
				     void *buffer, size_t *size)
{
	TEE_Result res;
	struct tee_ta_session *sess;
	struct tee_obj *o;
	const struct tee_cryp_obj_type_props *type_props;
	int idx;
	size_t raw_size;
	void *raw_data;

	res = tee_ta_get_current_session(&sess);
	if (res != TEE_SUCCESS)
		return res;

	res = tee_obj_get(sess->ctx, obj, &o);
	if (res != TEE_SUCCESS)
		return TEE_ERROR_ITEM_NOT_FOUND;

	/* Check that the object is initialized */
	if ((o->info.handleFlags & TEE_HANDLE_FLAG_INITIALIZED) == 0)
		return TEE_ERROR_ITEM_NOT_FOUND;

	/* Check that getting the attribute is allowed */
	if ((attr_id & TEE_ATTR_BIT_PROTECTED) == 0 &&
	    (o->info.objectUsage & TEE_USAGE_EXTRACTABLE) == 0)
		return TEE_ERROR_ACCESS_DENIED;

	type_props = tee_svc_find_type_props(o->info.objectType);
	if (type_props == NULL) {
		/* Unknown object type, "can't happen" */
		return TEE_ERROR_BAD_STATE;
	}

	idx = tee_svc_cryp_obj_find_type_attr_idx(attr_id, type_props);
	if ((idx < 0) || ((o->have_attrs & (1 << idx)) == 0))
		return TEE_ERROR_ITEM_NOT_FOUND;

	res = tee_svc_cryp_obj_get_raw_data(o, type_props, idx,
					    &raw_data, &raw_size);
	if (res != TEE_SUCCESS)
		return res;

	return tee_svc_cryp_obj_copy_out(sess, buffer, size,
					 type_props->type_attrs[idx].conv_func,
					 raw_data, raw_size);
}

static void bn_free(bignum **bn)
{
	if (*bn)
		crypto_ops.bignum.free(*bn);
	*bn = NULL;
}

static void free_rsa_keypair_s(void *p)
{
	struct rsa_keypair_s *s = (struct rsa_keypair_s *)p;
	bn_free(&s->d);
	bn_free(&s->N);
	bn_free(&s->p);
	bn_free(&s->q);
	bn_free(&s->qP);
	bn_free(&s->dP);
	bn_free(&s->dQ);
}

static void free_dsa_keypair_s(void *p)
{
	struct dsa_keypair_s *s = (struct dsa_keypair_s *)p;
	bn_free(&s->g);
	bn_free(&s->p);
	bn_free(&s->q);
	bn_free(&s->y);
	bn_free(&s->x);
}

static void free_rsa_public_key_s(void *p)
{
	struct rsa_public_key_s *s = (struct rsa_public_key_s *)p;
	bn_free(&s->e);
	bn_free(&s->N);
}

static void free_dsa_public_key_s(void *p)
{
	struct dsa_public_key_s *s = (struct dsa_public_key_s *)p;
	bn_free(&s->g);
	bn_free(&s->p);
	bn_free(&s->q);
	bn_free(&s->y);
}

static void free_dh_keypair_s(void *p)
{
	struct dh_keypair_s *s = (struct dh_keypair_s *)p;
	bn_free(&s->g);
	bn_free(&s->p);
	bn_free(&s->x);
	bn_free(&s->y);
	bn_free(&s->q);
	s->xbits = 0;
}

static int bn_prealloc(bignum **bn)
{
	if (crypto_ops.bignum.preallocate == NULL)
		return 1;
	*bn = crypto_ops.bignum.preallocate();
	return (*bn != NULL);
}

static TEE_Result new_rsa_keypair_s(struct rsa_keypair_s *s)
{
	if (!bn_prealloc(&s->e))
		goto err;
	if (!bn_prealloc(&s->d))
		goto err;
	if (!bn_prealloc(&s->N))
		goto err;
	if (!bn_prealloc(&s->p))
		goto err;
	if (!bn_prealloc(&s->q))
		goto err;
	if (!bn_prealloc(&s->qP))
		goto err;
	if (!bn_prealloc(&s->dP))
		goto err;
	if (!bn_prealloc(&s->dQ))
		goto err;
	return TEE_SUCCESS;
err:
	free_rsa_keypair_s(s);
	return TEE_ERROR_OUT_OF_MEMORY;
}

static TEE_Result new_rsa_public_key_s(struct rsa_public_key_s *s)
{
	if (!bn_prealloc(&s->e))
		goto err;
	if (!bn_prealloc(&s->N))
		goto err;
	return TEE_SUCCESS;
err:
	free_rsa_public_key_s(s);
	return TEE_ERROR_OUT_OF_MEMORY;
}

static TEE_Result new_dsa_keypair_s(struct dsa_keypair_s *s)
{
	if (!bn_prealloc(&s->g))
		goto err;
	if (!bn_prealloc(&s->p))
		goto err;
	if (!bn_prealloc(&s->q))
		goto err;
	if (!bn_prealloc(&s->y))
		goto err;
	if (!bn_prealloc(&s->x))
		goto err;
	return TEE_SUCCESS;
err:
	free_dsa_keypair_s(s);
	return TEE_ERROR_OUT_OF_MEMORY;
}

static TEE_Result new_dsa_public_key_s(struct dsa_public_key_s *s)
{
	if (!bn_prealloc(&s->g))
		goto err;
	if (!bn_prealloc(&s->p))
		goto err;
	if (!bn_prealloc(&s->q))
		goto err;
	if (!bn_prealloc(&s->y))
		goto err;
	return TEE_SUCCESS;
err:
	free_dsa_public_key_s(s);
	return TEE_ERROR_OUT_OF_MEMORY;
}

static TEE_Result new_dh_keypair_s(struct dh_keypair_s *s)
{
	if (!bn_prealloc(&s->g))
		goto err;
	if (!bn_prealloc(&s->p))
		goto err;
	if (!bn_prealloc(&s->y))
		goto err;
	if (!bn_prealloc(&s->x))
		goto err;
	if (!bn_prealloc(&s->q))
		goto err;
	return TEE_SUCCESS;
err:
	free_dh_keypair_s(s);
	return TEE_ERROR_OUT_OF_MEMORY;
}

static void copy_rsa_public_key_s(struct rsa_public_key_s *to,
				  const struct rsa_public_key_s *from)
{
	crypto_ops.bignum.copy(to->e, from->e);
	crypto_ops.bignum.copy(to->N, from->N);
}


static void copy_rsa_keypair_s(struct rsa_keypair_s *to,
			       const struct rsa_keypair_s *from)
{
	crypto_ops.bignum.copy(to->e, from->e);
	crypto_ops.bignum.copy(to->d, from->d);
	crypto_ops.bignum.copy(to->N, from->N);
	crypto_ops.bignum.copy(to->p, from->p);
	crypto_ops.bignum.copy(to->q, from->q);
	crypto_ops.bignum.copy(to->qP, from->qP);
	crypto_ops.bignum.copy(to->dP, from->dP);
	crypto_ops.bignum.copy(to->dQ, from->dQ);
}

static void copy_dsa_public_key_s(struct dsa_public_key_s *to,
				  const struct dsa_public_key_s *from)
{
	crypto_ops.bignum.copy(to->g, from->g);
	crypto_ops.bignum.copy(to->p, from->p);
	crypto_ops.bignum.copy(to->q, from->q);
	crypto_ops.bignum.copy(to->y, from->y);
}


static void copy_dsa_keypair_s(struct dsa_keypair_s *to,
			       const struct dsa_keypair_s *from)
{
	crypto_ops.bignum.copy(to->g, from->g);
	crypto_ops.bignum.copy(to->p, from->p);
	crypto_ops.bignum.copy(to->q, from->q);
	crypto_ops.bignum.copy(to->y, from->y);
	crypto_ops.bignum.copy(to->x, from->x);
}

static void copy_dh_keypair_s(struct dh_keypair_s *to,
			      const struct dh_keypair_s *from)
{
	crypto_ops.bignum.copy(to->g, from->g);
	crypto_ops.bignum.copy(to->p, from->p);
	crypto_ops.bignum.copy(to->y, from->y);
	crypto_ops.bignum.copy(to->x, from->x);
	crypto_ops.bignum.copy(to->q, from->q);
	to->xbits = from->xbits;
}

TEE_Result tee_svc_cryp_obj_alloc(TEE_ObjectType obj_type,
				  uint32_t max_obj_size, uint32_t *obj)
{
	TEE_Result res;
	struct tee_ta_session *sess;
	const struct tee_cryp_obj_type_props *type_props;
	struct tee_obj *o;

	res = tee_ta_get_current_session(&sess);
	if (res != TEE_SUCCESS)
		return res;

	/*
	 * Verify that maxObjectSize is supported and find out how
	 * much should be allocated.
	 */

	/* Find description of object */
	type_props = tee_svc_find_type_props(obj_type);
	if (type_props == NULL)
		return TEE_ERROR_NOT_SUPPORTED;

	/* Check that maxObjectSize follows restrictions */
	if (max_obj_size % type_props->quanta != 0)
		return TEE_ERROR_NOT_SUPPORTED;
	if (max_obj_size < type_props->min_size)
		return TEE_ERROR_NOT_SUPPORTED;
	if (max_obj_size > type_props->max_size)
		return TEE_ERROR_NOT_SUPPORTED;

	o = calloc(1, sizeof(*o));
	if (o == NULL)
		return TEE_ERROR_OUT_OF_MEMORY;
	o->data = calloc(1, type_props->alloc_size);
	if (o->data == NULL) {
		free(o);
		return TEE_ERROR_OUT_OF_MEMORY;
	}
	o->data_size = type_props->alloc_size;

	/*
	 * If we have a key structure, give crypto provider the opportunity
	 * to pre-allocate the bignums inside
	 */
#define PREALLOC_FOR(_type, _alloc, _finalize) \
	case _type: \
		if (_alloc(o->data) != TEE_SUCCESS) { \
			free(o->data); \
			free(o); \
			return TEE_ERROR_OUT_OF_MEMORY; \
		} \
		o->finalize = _finalize; \
		break

	switch (obj_type) {
		PREALLOC_FOR(TEE_TYPE_RSA_PUBLIC_KEY, new_rsa_public_key_s,
			     free_rsa_public_key_s);
		PREALLOC_FOR(TEE_TYPE_RSA_KEYPAIR, new_rsa_keypair_s,
			     free_rsa_keypair_s);
		PREALLOC_FOR(TEE_TYPE_DSA_PUBLIC_KEY, new_dsa_public_key_s,
			     free_dsa_public_key_s);
		PREALLOC_FOR(TEE_TYPE_DSA_KEYPAIR, new_dsa_keypair_s,
			     free_dsa_keypair_s);
		PREALLOC_FOR(TEE_TYPE_DH_KEYPAIR, new_dh_keypair_s,
			     free_dh_keypair_s);
		default:
			break;
	}
#undef PREALLOC_FOR

	o->info.objectType = obj_type;
	o->info.maxObjectSize = max_obj_size;
	o->info.objectUsage = TEE_USAGE_DEFAULT;
	o->info.handleFlags = 0;

	o->fd = -1;

	tee_obj_add(sess->ctx, o);

	res = tee_svc_copy_to_user(sess, obj, &o, sizeof(o));
	if (res != TEE_SUCCESS)
		tee_obj_close(sess->ctx, o);
	return res;
}

TEE_Result tee_svc_cryp_obj_close(uint32_t obj)
{
	TEE_Result res;
	struct tee_ta_session *sess;
	struct tee_obj *o;

	res = tee_ta_get_current_session(&sess);
	if (res != TEE_SUCCESS)
		return res;

	res = tee_obj_get(sess->ctx, obj, &o);
	if (res != TEE_SUCCESS)
		return res;

	/*
	 * If it's busy it's used by an operation, a client should never have
	 * this handle.
	 */
	if (o->busy)
		return TEE_ERROR_ITEM_NOT_FOUND;

	tee_obj_close(sess->ctx, o);
	return TEE_SUCCESS;
}

TEE_Result tee_svc_cryp_obj_reset(uint32_t obj)
{
	TEE_Result res;
	struct tee_ta_session *sess;
	struct tee_obj *o;

	res = tee_ta_get_current_session(&sess);
	if (res != TEE_SUCCESS)
		return res;

	res = tee_obj_get(sess->ctx, obj, &o);
	if (res != TEE_SUCCESS)
		return res;

	if ((o->info.handleFlags & TEE_HANDLE_FLAG_PERSISTENT) == 0) {
		memset(o->data, 0, o->data_size);
		o->info.objectSize = 0;
		o->info.objectUsage = TEE_USAGE_DEFAULT;
	} else {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	return TEE_SUCCESS;
}

static TEE_Result tee_svc_cryp_obj_store_attr_raw(struct tee_ta_session *sess,
						  uint16_t conv_func,
						  const TEE_Attribute *attr,
						  void *data, size_t data_size)
{
	TEE_Result res;

	if (attr == NULL)
		return TEE_ERROR_BAD_STATE;

	if (conv_func != TEE_TYPE_CONV_FUNC_VALUE &&
	    attr->content.ref.buffer == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	switch (conv_func) {
	case TEE_TYPE_CONV_FUNC_NONE:
		/* No conversion data size has to match exactly */
		if (attr->content.ref.length != data_size)
			return TEE_ERROR_BAD_PARAMETERS;
		return tee_svc_copy_from_user(sess, data,
					      attr->content.ref.buffer,
					      data_size);
	case TEE_TYPE_CONV_FUNC_SECRET:
		{
			struct tee_cryp_obj_secret *obj;

			if (!TEE_ALIGNMENT_IS_OK
			    (data, struct tee_cryp_obj_secret))
				 return TEE_ERROR_BAD_STATE;
			obj = (struct tee_cryp_obj_secret *)(void *)data;

			/* Data size has to fit in allocated buffer */
			if (attr->content.ref.length >
			    (data_size - sizeof(struct tee_cryp_obj_secret)))
				return TEE_ERROR_BAD_PARAMETERS;

			res = tee_svc_copy_from_user(sess, obj + 1,
						     attr->content.ref.buffer,
						     attr->content.ref.length);
			if (res == TEE_SUCCESS)
				obj->key_size = attr->content.ref.length;
			return res;
		}

	case TEE_TYPE_CONV_FUNC_BIGNUM:
		/* Check data can be accessed */
		res = tee_mmu_check_access_rights(
			sess->ctx,
			TEE_MEMORY_ACCESS_READ | TEE_MEMORY_ACCESS_ANY_OWNER,
			(tee_uaddr_t)attr->content.ref.buffer,
			attr->content.ref.length);
		if (res != TEE_SUCCESS)
			return res;

		/*
		 * Read the array of bytes (stored in attr->content.ref.buffer)
		 * and convert it to a bignum (pointed to by data)
		 */
		bignum *bn = *(bignum **)data;
		res = crypto_ops.bignum.bin2bn(attr->content.ref.buffer,
					       attr->content.ref.length,
					       bn);
		return res;

	case TEE_TYPE_CONV_FUNC_VALUE:
		/*
		 * a value attribute consists of two uint32 but have not
		 * seen anything that actaully would need that so this fills
		 * the data from the first value and discards the second value
		 */
		*(uint32_t *)data = attr->content.value.a;

		return TEE_SUCCESS;

	default:
		return TEE_ERROR_BAD_STATE;
	}
}

enum attr_usage {
	ATTR_USAGE_POPULATE,
	ATTR_USAGE_GENERATE_KEY
};

static TEE_Result tee_svc_cryp_check_attr(
		enum attr_usage usage,
		const struct tee_cryp_obj_type_props *type_props,
		TEE_Attribute *attrs,
		uint32_t attr_count)
{
	uint32_t required_flag;
	uint32_t opt_flag;
	bool all_opt_needed;
	uint32_t req_attrs = 0;
	uint32_t opt_grp_attrs = 0;
	uint32_t attrs_found = 0;
	size_t n;

	if (usage == ATTR_USAGE_POPULATE) {
		required_flag = TEE_TYPE_ATTR_REQUIRED;
		opt_flag = TEE_TYPE_ATTR_OPTIONAL_GROUP;
		all_opt_needed = true;
	} else {
		required_flag = TEE_TYPE_ATTR_GEN_KEY_REQ;
		opt_flag = TEE_TYPE_ATTR_GEN_KEY_OPT;
		all_opt_needed = false;
	}

	/*
	 * First find out which attributes are required and which belong to
	 * the optional group
	 */
	for (n = 0; n < type_props->num_type_attrs; n++) {
		uint32_t bit = 1 << n;
		uint32_t flags = type_props->type_attrs[n].flags;

		if (flags & required_flag)
			req_attrs |= bit;
		else if (flags & opt_flag)
			opt_grp_attrs |= bit;
	}

	/*
	 * Verify that all required attributes are in place and
	 * that the same attribute isn't repeated.
	 */
	for (n = 0; n < attr_count; n++) {
		int idx =
		    tee_svc_cryp_obj_find_type_attr_idx(attrs[n].attributeID,
							type_props);
		if (idx >= 0) {
			uint32_t bit = 1 << idx;

			if ((attrs_found & bit) != 0)
				return TEE_ERROR_ITEM_NOT_FOUND;

			attrs_found |= bit;
		}
	}
	/* Required attribute missing */
	if ((attrs_found & req_attrs) != req_attrs)
		return TEE_ERROR_ITEM_NOT_FOUND;

	/*
	 * If the flag says that "if one of the optional attributes are included
	 * all of them has to be included" this must be checked.
	 */
	if (all_opt_needed && (attrs_found & opt_grp_attrs) != 0 &&
	    (attrs_found & opt_grp_attrs) != opt_grp_attrs)
		return TEE_ERROR_ITEM_NOT_FOUND;

	return TEE_SUCCESS;
}

static TEE_Result tee_svc_cryp_obj_populate_type(
		struct tee_ta_session *sess,
		struct tee_obj *o,
		const struct tee_cryp_obj_type_props *type_props,
		const TEE_Attribute *attrs,
		uint32_t attr_count)
{
	TEE_Result res;
	uint32_t have_attrs = 0;
	size_t obj_size = 0;
	size_t n;

	for (n = 0; n < attr_count; n++) {
		size_t raw_size;
		void *raw_data;
		int idx =
		    tee_svc_cryp_obj_find_type_attr_idx(attrs[n].attributeID,
							type_props);
		if (idx < 0)
			continue;

		have_attrs |= 1 << idx;

		res = tee_svc_cryp_obj_get_raw_data(o, type_props, idx,
						    &raw_data, &raw_size);
		if (res != TEE_SUCCESS)
			return res;

		res =
		    tee_svc_cryp_obj_store_attr_raw(
			    sess, type_props->type_attrs[idx].conv_func,
			    attrs + n, raw_data, raw_size);
		if (res != TEE_SUCCESS)
			return res;

		/*
		 * First attr_idx signifies the attribute that gives the size
		 * of the object
		 */
		if (type_props->type_attrs[idx].flags &
		    TEE_TYPE_ATTR_SIZE_INDICATOR) {
			obj_size += attrs[n].content.ref.length * 8;
		}
	}

	/*
	 * We have to do it like this because the parity bits aren't counted
	 * when telling the size of the key in bits.
	 */
	if (o->info.objectType == TEE_TYPE_DES ||
	    o->info.objectType == TEE_TYPE_DES3)
		obj_size -= obj_size / 8; /* Exclude parity in size of key */

	o->have_attrs = have_attrs;
	o->info.objectSize = obj_size;
	return TEE_SUCCESS;
}

TEE_Result tee_svc_cryp_obj_populate(uint32_t obj, TEE_Attribute *attrs,
				     uint32_t attr_count)
{
	TEE_Result res;
	struct tee_ta_session *sess;
	struct tee_obj *o;
	const struct tee_cryp_obj_type_props *type_props;

	res = tee_ta_get_current_session(&sess);
	if (res != TEE_SUCCESS)
		return res;

	res = tee_obj_get(sess->ctx, obj, &o);
	if (res != TEE_SUCCESS)
		return res;

	/* Must be a transient object */
	if ((o->info.handleFlags & TEE_HANDLE_FLAG_PERSISTENT) != 0)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Must not be initialized already */
	if ((o->info.handleFlags & TEE_HANDLE_FLAG_INITIALIZED) != 0)
		return TEE_ERROR_BAD_PARAMETERS;

	type_props = tee_svc_find_type_props(o->info.objectType);
	if (type_props == NULL)
		return TEE_ERROR_NOT_IMPLEMENTED;

	res = tee_svc_cryp_check_attr(ATTR_USAGE_POPULATE, type_props, attrs,
				      attr_count);
	if (res != TEE_SUCCESS)
		return res;

	res = tee_svc_cryp_obj_populate_type(sess, o, type_props, attrs,
					     attr_count);
	if (res == TEE_SUCCESS)
		o->info.handleFlags |= TEE_HANDLE_FLAG_INITIALIZED;

	return res;
}

TEE_Result tee_svc_cryp_obj_copy(uint32_t dst, uint32_t src)
{
	TEE_Result res;
	struct tee_ta_session *sess;
	struct tee_obj *dst_o;
	struct tee_obj *src_o;

	res = tee_ta_get_current_session(&sess);
	if (res != TEE_SUCCESS)
		return res;

	res = tee_obj_get(sess->ctx, dst, &dst_o);
	if (res != TEE_SUCCESS)
		return res;

	res = tee_obj_get(sess->ctx, src, &src_o);
	if (res != TEE_SUCCESS)
		return res;

	if ((src_o->info.handleFlags & TEE_HANDLE_FLAG_INITIALIZED) == 0)
		return TEE_ERROR_BAD_PARAMETERS;
	if ((dst_o->info.handleFlags & TEE_HANDLE_FLAG_PERSISTENT) != 0)
		return TEE_ERROR_BAD_PARAMETERS;
	if ((dst_o->info.handleFlags & TEE_HANDLE_FLAG_INITIALIZED) != 0)
		return TEE_ERROR_BAD_PARAMETERS;

	if (dst_o->info.objectType == src_o->info.objectType) {
		/* Copy whole data */

		if (dst_o->data_size != src_o->data_size)
			return TEE_ERROR_BAD_STATE;

		dst_o->have_attrs = src_o->have_attrs;

		switch (src_o->info.objectType) {

		case TEE_TYPE_RSA_PUBLIC_KEY:

			copy_rsa_public_key_s((struct rsa_public_key_s *)
					      src_o->data,
					      (struct rsa_public_key_s *)
					      dst_o->data);
			break;

		case TEE_TYPE_RSA_KEYPAIR:

			copy_rsa_keypair_s((struct rsa_keypair_s *)
					   src_o->data,
					   (struct rsa_keypair_s *)
					   dst_o->data);
			break;

		case TEE_TYPE_DSA_PUBLIC_KEY:

			copy_dsa_public_key_s((struct dsa_public_key_s *)
					      src_o->data,
					      (struct dsa_public_key_s *)
					      dst_o->data);
			break;

		case TEE_TYPE_DSA_KEYPAIR:

			copy_dsa_keypair_s((struct dsa_keypair_s *)
					   src_o->data,
					   (struct dsa_keypair_s *)
					   dst_o->data);
			break;

		case TEE_TYPE_DH_KEYPAIR:

			copy_dh_keypair_s((struct dh_keypair_s *)
					  src_o->data,
					  (struct dh_keypair_s *)
					  dst_o->data);
			break;

		default:
			/* Generic case */
			memcpy(dst_o->data, src_o->data, src_o->data_size);
		}
	} else if (dst_o->info.objectType == TEE_TYPE_RSA_PUBLIC_KEY &&
		   src_o->info.objectType == TEE_TYPE_RSA_KEYPAIR) {
		/* Extract public key from RSA key pair */
		struct rsa_keypair_s *key_pair = src_o->data;
		struct rsa_public_key_s *pub_key = dst_o->data;
		size_t n;

		crypto_ops.bignum.copy(pub_key->e, key_pair->e);
		crypto_ops.bignum.copy(pub_key->N, key_pair->N);

		/* Set the attributes */
		dst_o->have_attrs = 0;
		for (n = 0; n < TEE_ARRAY_SIZE(tee_cryp_obj_rsa_pub_key_attrs);
		     n++)
			dst_o->have_attrs |= 1 << n;

	} else if (dst_o->info.objectType == TEE_TYPE_DSA_PUBLIC_KEY &&
		   src_o->info.objectType == TEE_TYPE_DSA_KEYPAIR) {
		/* Extract public key from DSA key pair */
		struct dsa_keypair_s *key_pair = src_o->data;
		struct dsa_public_key_s *pub_key = dst_o->data;
		size_t n;

		crypto_ops.bignum.copy(pub_key->g, key_pair->g);
		crypto_ops.bignum.copy(pub_key->p, key_pair->p);
		crypto_ops.bignum.copy(pub_key->q, key_pair->q);
		crypto_ops.bignum.copy(pub_key->y, key_pair->y);

		/* Set the attributes */
		dst_o->have_attrs = 0;
		for (n = 0; n < TEE_ARRAY_SIZE(tee_cryp_obj_dsa_pub_key_attrs);
		     n++)
			dst_o->have_attrs |= 1 << n;

	} else
		return TEE_ERROR_BAD_PARAMETERS;

	dst_o->info.handleFlags |= TEE_HANDLE_FLAG_INITIALIZED;
	dst_o->info.objectSize = src_o->info.objectSize;
	dst_o->info.objectUsage = src_o->info.objectUsage;
	return TEE_SUCCESS;
}

static TEE_Result tee_svc_obj_generate_key_rsa(
	struct tee_obj *o, const struct tee_cryp_obj_type_props *type_props,
	uint32_t key_size)
{
	TEE_Result res;
	struct rsa_keypair_s *tee_rsa_key;

	TEE_ASSERT(sizeof(struct rsa_keypair_s) == o->data_size);
	tee_rsa_key = (struct rsa_keypair_s *)o->data;
	res = crypto_ops.acipher.gen_rsa_key(tee_rsa_key, key_size);
	if (res != TEE_SUCCESS)
		return res;

	/* Set bits for all known attributes for this object type */
	o->have_attrs = (1 << type_props->num_type_attrs) - 1;
	return TEE_SUCCESS;
}

static TEE_Result tee_svc_obj_generate_key_dsa(
	struct tee_obj *o, const struct tee_cryp_obj_type_props *type_props,
	uint32_t key_size)
{
	TEE_Result res;
	struct dsa_keypair_s *tee_dsa_key;

	TEE_ASSERT(sizeof(struct dsa_keypair_s) == o->data_size);
	tee_dsa_key = (struct dsa_keypair_s *)o->data;
	res = crypto_ops.acipher.gen_dsa_key(tee_dsa_key, key_size);
	if (res != TEE_SUCCESS)
		return res;

	/* Set bits for all known attributes for this object type */
	o->have_attrs = (1 << type_props->num_type_attrs) - 1;
	return TEE_SUCCESS;
}

static TEE_Result tee_svc_obj_generate_key_dh(
	struct tee_ta_session *sess,
	struct tee_obj *o, const struct tee_cryp_obj_type_props *type_props,
	uint32_t key_size, const TEE_Attribute *params, uint32_t param_count)
{
	TEE_Result res;
	struct dh_keypair_s *tee_dh_key;
	bignum *dh_q = NULL;
	uint32_t dh_xbits = 0;

	TEE_ASSERT(sizeof(struct dh_keypair_s) == o->data_size);

	/* Copy the present attributes into the obj before starting */
	res = tee_svc_cryp_obj_populate_type(
			sess, o, type_props, params, param_count);
	if (res != TEE_SUCCESS)
		return res;

	tee_dh_key = (struct dh_keypair_s *)o->data;

	if (GET_ATTRIBUTE(o, type_props, TEE_ATTR_DH_SUBPRIME))
		dh_q = tee_dh_key->q;
	if (GET_ATTRIBUTE(o, type_props, TEE_ATTR_DH_X_BITS))
		dh_xbits = tee_dh_key->xbits;
	res = crypto_ops.acipher.gen_dh_key(tee_dh_key, dh_q, dh_xbits);
	if (res != TEE_SUCCESS)
		return res;

	/* Set bits for the generated public and private key */
	SET_ATTRIBUTE(o, type_props, TEE_ATTR_DH_PUBLIC_VALUE);
	SET_ATTRIBUTE(o, type_props, TEE_ATTR_DH_PRIVATE_VALUE);
	SET_ATTRIBUTE(o, type_props, TEE_ATTR_DH_X_BITS);
	return TEE_SUCCESS;
}

TEE_Result tee_svc_obj_generate_key(
	uint32_t obj, uint32_t key_size,
	const TEE_Attribute *params, uint32_t param_count)
{
	TEE_Result res;
	struct tee_ta_session *sess;
	const struct tee_cryp_obj_type_props *type_props;
	struct tee_obj *o;
	struct tee_cryp_obj_secret *key;
	size_t byte_size;

	res = tee_ta_get_current_session(&sess);
	if (res != TEE_SUCCESS)
		return res;

	res = tee_obj_get(sess->ctx, obj, &o);
	if (res != TEE_SUCCESS)
		return res;

	/* Must be a transient object */
	if ((o->info.handleFlags & TEE_HANDLE_FLAG_PERSISTENT) != 0)
		return TEE_ERROR_BAD_STATE;

	/* Must not be initialized already */
	if ((o->info.handleFlags & TEE_HANDLE_FLAG_INITIALIZED) != 0)
		return TEE_ERROR_BAD_STATE;

	/* Find description of object */
	type_props = tee_svc_find_type_props(o->info.objectType);
	if (type_props == NULL)
		return TEE_ERROR_NOT_SUPPORTED;

	/* Check that maxObjectSize follows restrictions */
	if (key_size % type_props->quanta != 0)
		return TEE_ERROR_NOT_SUPPORTED;
	if (key_size < type_props->min_size)
		return TEE_ERROR_NOT_SUPPORTED;
	if (key_size > type_props->max_size)
		return TEE_ERROR_NOT_SUPPORTED;

	res = tee_svc_cryp_check_attr(ATTR_USAGE_GENERATE_KEY, type_props,
				      (TEE_Attribute *)params, param_count);
	if (res != TEE_SUCCESS)
		return res;

	switch (o->info.objectType) {
	case TEE_TYPE_AES:
	case TEE_TYPE_DES:
	case TEE_TYPE_DES3:
	case TEE_TYPE_HMAC_MD5:
	case TEE_TYPE_HMAC_SHA1:
	case TEE_TYPE_HMAC_SHA224:
	case TEE_TYPE_HMAC_SHA256:
	case TEE_TYPE_HMAC_SHA384:
	case TEE_TYPE_HMAC_SHA512:
	case TEE_TYPE_GENERIC_SECRET:
		byte_size = key_size / 8;

		/*
		 * We have to do it like this because the parity bits aren't
		 * counted when telling the size of the key in bits.
		 */
		if (o->info.objectType == TEE_TYPE_DES ||
		    o->info.objectType == TEE_TYPE_DES3) {
			byte_size = (key_size + key_size / 7) / 8;
		}

		key = (struct tee_cryp_obj_secret *)o->data;
		if (byte_size > (o->data_size - sizeof(*key)))
			return TEE_ERROR_EXCESS_DATA;

		res = get_rng_array((void *)(key + 1), byte_size);
		if (res != TEE_SUCCESS)
			return res;

		/* Force the last bit to have exactly a value on byte_size */
		((char *)key)[sizeof(key->key_size) + byte_size - 1] |= 0x80;
		key->key_size = byte_size;

		/* Set bits for all known attributes for this object type */
		o->have_attrs = (1 << type_props->num_type_attrs) - 1;

		break;

	case TEE_TYPE_RSA_KEYPAIR:
		res = tee_svc_obj_generate_key_rsa(o, type_props, key_size);
		if (res != TEE_SUCCESS)
			return res;
		break;

	case TEE_TYPE_DSA_KEYPAIR:
		res = tee_svc_obj_generate_key_dsa(o, type_props, key_size);
		if (res != TEE_SUCCESS)
			return res;
		break;

	case TEE_TYPE_DH_KEYPAIR:
		res = tee_svc_obj_generate_key_dh(
			sess, o, type_props, key_size, params, param_count);
		if (res != TEE_SUCCESS)
			return res;
		break;

	default:
		return TEE_ERROR_BAD_FORMAT;
	}

	o->info.objectSize = key_size;
	o->info.handleFlags |= TEE_HANDLE_FLAG_INITIALIZED;
	return TEE_SUCCESS;
}

static TEE_Result tee_svc_cryp_get_state(struct tee_ta_session *sess,
					 uint32_t state_id,
					 struct tee_cryp_state **state)
{
	struct tee_cryp_state *s;

	TAILQ_FOREACH(s, &sess->ctx->cryp_states, link) {
		if (state_id == (uint32_t) s) {
			*state = s;
			return TEE_SUCCESS;
		}
	}
	return TEE_ERROR_BAD_PARAMETERS;
}

static void cryp_state_free(struct tee_ta_ctx *ctx, struct tee_cryp_state *cs)
{
	struct tee_obj *o;

	if (tee_obj_get(ctx, cs->key1, &o) == TEE_SUCCESS)
		tee_obj_close(ctx, o);
	if (tee_obj_get(ctx, cs->key2, &o) == TEE_SUCCESS)
		tee_obj_close(ctx, o);

	TAILQ_REMOVE(&ctx->cryp_states, cs, link);
	if (cs->ctx_finalize != NULL)
		cs->ctx_finalize(cs->ctx, cs->algo);
	free(cs->ctx);
	free(cs);
}

static TEE_Result tee_svc_cryp_check_key_type(const struct tee_obj *o,
					      uint32_t algo,
					      TEE_OperationMode mode)
{
	uint32_t req_key_type;

	switch (TEE_ALG_GET_MAIN_ALG(algo)) {
	case TEE_MAIN_ALGO_MD5:
		req_key_type = TEE_TYPE_HMAC_MD5;
		break;
	case TEE_MAIN_ALGO_SHA1:
		req_key_type = TEE_TYPE_HMAC_SHA1;
		break;
	case TEE_MAIN_ALGO_SHA224:
		req_key_type = TEE_TYPE_HMAC_SHA224;
		break;
	case TEE_MAIN_ALGO_SHA256:
		req_key_type = TEE_TYPE_HMAC_SHA256;
		break;
	case TEE_MAIN_ALGO_SHA384:
		req_key_type = TEE_TYPE_HMAC_SHA384;
		break;
	case TEE_MAIN_ALGO_SHA512:
		req_key_type = TEE_TYPE_HMAC_SHA512;
		break;
	case TEE_MAIN_ALGO_AES:
		req_key_type = TEE_TYPE_AES;
		break;
	case TEE_MAIN_ALGO_DES:
		req_key_type = TEE_TYPE_DES;
		break;
	case TEE_MAIN_ALGO_DES3:
		req_key_type = TEE_TYPE_DES3;
		break;
	case TEE_MAIN_ALGO_RSA:
		if (mode == TEE_MODE_ENCRYPT || mode == TEE_MODE_VERIFY)
			req_key_type = TEE_TYPE_RSA_PUBLIC_KEY;
		else
			req_key_type = TEE_TYPE_RSA_KEYPAIR;
		break;
	case TEE_MAIN_ALGO_DSA:
		if (mode == TEE_MODE_ENCRYPT || mode == TEE_MODE_VERIFY)
			req_key_type = TEE_TYPE_DSA_PUBLIC_KEY;
		else
			req_key_type = TEE_TYPE_DSA_KEYPAIR;
		break;
	case TEE_MAIN_ALGO_DH:
		req_key_type = TEE_TYPE_DH_KEYPAIR;
		break;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (req_key_type != o->info.objectType)
		return TEE_ERROR_BAD_PARAMETERS;
	return TEE_SUCCESS;
}

TEE_Result tee_svc_cryp_state_alloc(uint32_t algo, uint32_t mode,
				    uint32_t key1, uint32_t key2,
				    uint32_t *state)
{
	TEE_Result res;
	struct tee_cryp_state *cs;
	struct tee_ta_session *sess;
	struct tee_obj *o1 = NULL;
	struct tee_obj *o2 = NULL;

	res = tee_ta_get_current_session(&sess);
	if (res != TEE_SUCCESS)
		return res;

	if (key1 != 0) {
		res = tee_obj_get(sess->ctx, key1, &o1);
		if (res != TEE_SUCCESS)
			return res;
		if (o1->busy)
			return TEE_ERROR_BAD_PARAMETERS;
		res = tee_svc_cryp_check_key_type(o1, algo, mode);
		if (res != TEE_SUCCESS)
			return res;
	}
	if (key2 != 0) {
		res = tee_obj_get(sess->ctx, key2, &o2);
		if (res != TEE_SUCCESS)
			return res;
		if (o2->busy)
			return TEE_ERROR_BAD_PARAMETERS;
		res = tee_svc_cryp_check_key_type(o2, algo, mode);
		if (res != TEE_SUCCESS)
			return res;
	}

	cs = calloc(1, sizeof(struct tee_cryp_state));
	if (cs == NULL)
		return TEE_ERROR_OUT_OF_MEMORY;
	TAILQ_INSERT_TAIL(&sess->ctx->cryp_states, cs, link);
	cs->algo = algo;
	cs->mode = mode;

	switch (TEE_ALG_GET_CLASS(algo)) {
	case TEE_OPERATION_CIPHER:
		if ((algo == TEE_ALG_AES_XTS && (key1 == 0 || key2 == 0)) ||
		    (algo != TEE_ALG_AES_XTS && (key1 == 0 || key2 != 0))) {
			res = TEE_ERROR_BAD_PARAMETERS;
		} else {
			res = crypto_ops.cipher.get_ctx_size(algo,
							     &cs->ctx_size);
			if (res != TEE_SUCCESS)
				break;
			cs->ctx = calloc(1, cs->ctx_size);
			if (cs->ctx == NULL)
				res = TEE_ERROR_OUT_OF_MEMORY;
		}
		break;
	case TEE_OPERATION_AE:
		if (key1 == 0 || key2 != 0) {
			res = TEE_ERROR_BAD_PARAMETERS;
		} else {
			res = crypto_ops.authenc.get_ctx_size(algo, &cs->ctx_size);
			if (res != TEE_SUCCESS)
				break;
			cs->ctx = calloc(1, cs->ctx_size);
			if (cs->ctx == NULL)
				res = TEE_ERROR_OUT_OF_MEMORY;
		}
		break;
	case TEE_OPERATION_MAC:
		if (key1 == 0 || key2 != 0) {
			res = TEE_ERROR_BAD_PARAMETERS;
		} else {
			res = crypto_ops.mac.get_ctx_size(algo, &cs->ctx_size);
			if (res != TEE_SUCCESS)
				break;
			cs->ctx = calloc(1, cs->ctx_size);
			if (cs->ctx == NULL)
				res = TEE_ERROR_OUT_OF_MEMORY;
		}
		break;
	case TEE_OPERATION_DIGEST:
		if (key1 != 0 || key2 != 0) {
			res = TEE_ERROR_BAD_PARAMETERS;
		} else {
			res = crypto_ops.hash.get_ctx_size(algo, &cs->ctx_size);
			if (res != TEE_SUCCESS)
				break;
			cs->ctx = calloc(1, cs->ctx_size);
			if (cs->ctx == NULL)
				res = TEE_ERROR_OUT_OF_MEMORY;
		}
		break;
	case TEE_OPERATION_ASYMMETRIC_CIPHER:
	case TEE_OPERATION_ASYMMETRIC_SIGNATURE:
		if (key1 == 0 || key2 != 0)
			res = TEE_ERROR_BAD_PARAMETERS;
		break;
	case TEE_OPERATION_KEY_DERIVATION:
		if (key1 == 0 || key2 != 0)
			res = TEE_ERROR_BAD_PARAMETERS;
		break;
	default:
		res = TEE_ERROR_NOT_SUPPORTED;
		break;
	}
	if (res != TEE_SUCCESS)
		goto out;

	res = tee_svc_copy_to_user(sess, state, &cs, sizeof(uint32_t));
	if (res != TEE_SUCCESS)
		goto out;

	/* Register keys */
	if (o1 != NULL) {
		o1->busy = true;
		cs->key1 = key1;
	}
	if (o2 != NULL) {
		o2->busy = true;
		cs->key2 = key2;
	}

out:
	if (res != TEE_SUCCESS)
		cryp_state_free(sess->ctx, cs);
	return res;
}

TEE_Result tee_svc_cryp_state_copy(uint32_t dst, uint32_t src)
{
	TEE_Result res;
	struct tee_cryp_state *cs_dst;
	struct tee_cryp_state *cs_src;
	struct tee_ta_session *sess;

	res = tee_ta_get_current_session(&sess);
	if (res != TEE_SUCCESS)
		return res;

	res = tee_svc_cryp_get_state(sess, dst, &cs_dst);
	if (res != TEE_SUCCESS)
		return res;
	res = tee_svc_cryp_get_state(sess, src, &cs_src);
	if (res != TEE_SUCCESS)
		return res;
	if (cs_dst->algo != cs_src->algo || cs_dst->mode != cs_src->mode)
		return TEE_ERROR_BAD_PARAMETERS;
	/* "Can't happen" */
	if (cs_dst->ctx_size != cs_src->ctx_size)
		return TEE_ERROR_BAD_STATE;

	memcpy(cs_dst->ctx, cs_src->ctx, cs_src->ctx_size);
	return TEE_SUCCESS;
}

void tee_svc_cryp_free_states(struct tee_ta_ctx *ctx)
{
	struct tee_cryp_state_head *states = &ctx->cryp_states;

	while (!TAILQ_EMPTY(states))
		cryp_state_free(ctx, TAILQ_FIRST(states));
}

TEE_Result tee_svc_cryp_state_free(uint32_t state)
{
	TEE_Result res;
	struct tee_cryp_state *cs;
	struct tee_ta_session *sess;

	res = tee_ta_get_current_session(&sess);
	if (res != TEE_SUCCESS)
		return res;

	res = tee_svc_cryp_get_state(sess, state, &cs);
	if (res != TEE_SUCCESS)
		return res;
	cryp_state_free(sess->ctx, cs);
	return TEE_SUCCESS;
}

/* iv and iv_len are ignored for some algorithms */
TEE_Result tee_svc_hash_init(uint32_t state, const void *iv, size_t iv_len)
{
	TEE_Result res;
	struct tee_cryp_state *cs;
	struct tee_ta_session *sess;

	res = tee_ta_get_current_session(&sess);
	if (res != TEE_SUCCESS)
		return res;

	res = tee_svc_cryp_get_state(sess, state, &cs);
	if (res != TEE_SUCCESS)
		return res;

	switch (TEE_ALG_GET_CLASS(cs->algo)) {
	case TEE_OPERATION_DIGEST:
		res = crypto_ops.hash.init(cs->ctx, cs->algo);
		if (res != TEE_SUCCESS)
			return res;
		break;
	case TEE_OPERATION_MAC:
		{
			struct tee_obj *o;
			struct tee_cryp_obj_secret *key;

			res = tee_obj_get(sess->ctx, cs->key1, &o);
			if (res != TEE_SUCCESS)
				return res;
			if ((o->info.handleFlags &
			     TEE_HANDLE_FLAG_INITIALIZED) == 0)
				return TEE_ERROR_BAD_PARAMETERS;

			key = (struct tee_cryp_obj_secret *)o->data;
			res = crypto_ops.mac.init(cs->ctx, cs->algo, (void *)(key + 1),
					   key->key_size);
			if (res != TEE_SUCCESS)
				return res;
			break;
		}
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}

	return TEE_SUCCESS;
}

TEE_Result tee_svc_hash_update(uint32_t state, const void *chunk,
			       size_t chunk_size)
{
	TEE_Result res;
	struct tee_cryp_state *cs;
	struct tee_ta_session *sess;

	res = tee_ta_get_current_session(&sess);
	if (res != TEE_SUCCESS)
		return res;

	res = tee_mmu_check_access_rights(sess->ctx,
					  TEE_MEMORY_ACCESS_READ |
					  TEE_MEMORY_ACCESS_ANY_OWNER,
					  (tee_uaddr_t)chunk, chunk_size);
	if (res != TEE_SUCCESS)
		return res;

	res = tee_svc_cryp_get_state(sess, state, &cs);
	if (res != TEE_SUCCESS)
		return res;

	switch (TEE_ALG_GET_CLASS(cs->algo)) {
	case TEE_OPERATION_DIGEST:
		res = crypto_ops.hash.update(cs->ctx, cs->algo, chunk, chunk_size);
		if (res != TEE_SUCCESS)
			return res;
		break;
	case TEE_OPERATION_MAC:
		res = crypto_ops.mac.update(cs->ctx, cs->algo, chunk, chunk_size);
		if (res != TEE_SUCCESS)
			return res;
		break;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}

	return TEE_SUCCESS;
}

TEE_Result tee_svc_hash_final(uint32_t state, const void *chunk,
			      size_t chunk_size, void *hash, size_t *hash_len)
{
	TEE_Result res, res2;
	size_t hash_size;
	size_t hlen;
	struct tee_cryp_state *cs;
	struct tee_ta_session *sess;

	res = tee_ta_get_current_session(&sess);
	if (res != TEE_SUCCESS)
		return res;

	res = tee_mmu_check_access_rights(sess->ctx,
					  TEE_MEMORY_ACCESS_READ |
					  TEE_MEMORY_ACCESS_ANY_OWNER,
					  (tee_uaddr_t)chunk, chunk_size);
	if (res != TEE_SUCCESS)
		return res;

	res = tee_svc_copy_from_user(sess, &hlen, hash_len, sizeof(size_t));
	if (res != TEE_SUCCESS)
		return res;

	res = tee_mmu_check_access_rights(sess->ctx,
					  TEE_MEMORY_ACCESS_READ |
					  TEE_MEMORY_ACCESS_WRITE |
					  TEE_MEMORY_ACCESS_ANY_OWNER,
					  (tee_uaddr_t)hash, hlen);
	if (res != TEE_SUCCESS)
		return res;

	res = tee_svc_cryp_get_state(sess, state, &cs);
	if (res != TEE_SUCCESS)
		return res;

	switch (TEE_ALG_GET_CLASS(cs->algo)) {
	case TEE_OPERATION_DIGEST:
		res = crypto_ops.hash.get_digest_size(cs->algo, &hash_size);
		if (res != TEE_SUCCESS)
			return res;
		if (*hash_len < hash_size) {
			res = TEE_ERROR_SHORT_BUFFER;
			goto out;
		}

		res = crypto_ops.hash.update(cs->ctx, cs->algo, chunk, chunk_size);
		if (res != TEE_SUCCESS)
			return res;
		res = crypto_ops.hash.final(cs->ctx, cs->algo, hash, hash_size);
		if (res != TEE_SUCCESS)
			return res;
		break;
	case TEE_OPERATION_MAC:
		res = crypto_ops.mac.get_digest_size(cs->algo, &hash_size);
		if (res != TEE_SUCCESS)
			return res;
		if (*hash_len < hash_size) {
			res = TEE_ERROR_SHORT_BUFFER;
			goto out;
		}

		res = crypto_ops.mac.final(cs->ctx, cs->algo, chunk, chunk_size, hash,
				    hash_size);
		if (res != TEE_SUCCESS)
			return res;
		break;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
out:
	res2 =
	    tee_svc_copy_to_user(sess, hash_len, &hash_size, sizeof(*hash_len));
	if (res2 != TEE_SUCCESS)
		return res2;
	return res;
}

TEE_Result tee_svc_cipher_init(uint32_t state, const void *iv, size_t iv_len)
{
	TEE_Result res;
	struct tee_cryp_state *cs;
	struct tee_ta_session *sess;
	struct tee_obj *o;
	struct tee_cryp_obj_secret *key1;

	res = tee_ta_get_current_session(&sess);
	if (res != TEE_SUCCESS)
		return res;

	res = tee_svc_cryp_get_state(sess, state, &cs);
	if (res != TEE_SUCCESS)
		return res;

	res = tee_mmu_check_access_rights(sess->ctx,
					  TEE_MEMORY_ACCESS_READ |
					  TEE_MEMORY_ACCESS_ANY_OWNER,
					  (tee_uaddr_t) iv, iv_len);
	if (res != TEE_SUCCESS)
		return res;

	res = tee_obj_get(sess->ctx, cs->key1, &o);
	if (res != TEE_SUCCESS)
		return res;
	if ((o->info.handleFlags & TEE_HANDLE_FLAG_INITIALIZED) == 0)
		return TEE_ERROR_BAD_PARAMETERS;

	key1 = (struct tee_cryp_obj_secret *)o->data;

	if (tee_obj_get(sess->ctx, cs->key2, &o) == TEE_SUCCESS) {
		struct tee_cryp_obj_secret *key2 =
		    (struct tee_cryp_obj_secret *)o->data;

		if ((o->info.handleFlags & TEE_HANDLE_FLAG_INITIALIZED) == 0)
			return TEE_ERROR_BAD_PARAMETERS;

		res = crypto_ops.cipher.init(cs->ctx, cs->algo, cs->mode,
					     (uint8_t *)(key1 + 1),
					     key1->key_size,
					     (uint8_t *)(key2 + 1),
					     key2->key_size,
					     iv, iv_len);
	} else {
		res = crypto_ops.cipher.init(cs->ctx, cs->algo, cs->mode,
					     (uint8_t *)(key1 + 1),
					     key1->key_size,
					     NULL,
					     0,
					     iv, iv_len);
	}
	if (res != TEE_SUCCESS)
		return res;

	cs->ctx_finalize = crypto_ops.cipher.final;
	return TEE_SUCCESS;
}

static TEE_Result tee_svc_cipher_update_helper(uint32_t state, bool last_block,
					       const void *src, size_t src_len,
					       void *dst, size_t *dst_len)
{
	TEE_Result res;
	struct tee_cryp_state *cs;
	struct tee_ta_session *sess;
	size_t dlen;

	res = tee_ta_get_current_session(&sess);
	if (res != TEE_SUCCESS)
		return res;

	res = tee_svc_cryp_get_state(sess, state, &cs);
	if (res != TEE_SUCCESS)
		return res;

	res = tee_mmu_check_access_rights(sess->ctx,
					  TEE_MEMORY_ACCESS_READ |
					  TEE_MEMORY_ACCESS_ANY_OWNER,
					  (tee_uaddr_t)src, src_len);
	if (res != TEE_SUCCESS)
		return res;

	if (dst_len == NULL) {
		dlen = 0;
	} else {
		res =
		    tee_svc_copy_from_user(sess, &dlen, dst_len,
					   sizeof(size_t));
		if (res != TEE_SUCCESS)
			return res;

		res = tee_mmu_check_access_rights(sess->ctx,
						  TEE_MEMORY_ACCESS_READ |
						  TEE_MEMORY_ACCESS_WRITE |
						  TEE_MEMORY_ACCESS_ANY_OWNER,
						  (tee_uaddr_t)dst, dlen);
		if (res != TEE_SUCCESS)
			return res;
	}

	if (dlen < src_len) {
		res = TEE_ERROR_SHORT_BUFFER;
		goto out;
	}

	if (src_len > 0) {
		/* Permit src_len == 0 to finalize the operation */
		res = crypto_ops.cipher.update(cs->ctx, cs->algo, cs->mode, last_block,
					src, src_len, dst);
	}

	if (last_block && cs->ctx_finalize != NULL) {
		cs->ctx_finalize(cs->ctx, cs->mode);
		cs->ctx_finalize = NULL;
	}

out:
	if ((res == TEE_SUCCESS || res == TEE_ERROR_SHORT_BUFFER) &&
	    dst_len != NULL) {
		TEE_Result res2 = tee_svc_copy_to_user(sess, dst_len, &src_len,
						       sizeof(size_t));
		if (res2 != TEE_SUCCESS)
			res = res2;
	}

	return res;
}

TEE_Result tee_svc_cipher_update(uint32_t state, const void *src,
				 size_t src_len, void *dst, size_t *dst_len)
{
	return tee_svc_cipher_update_helper(state, false /* last_block */,
					    src, src_len, dst, dst_len);
}

TEE_Result tee_svc_cipher_final(uint32_t state, const void *src,
				size_t src_len, void *dst, size_t *dst_len)
{
	return tee_svc_cipher_update_helper(state, true /* last_block */,
					    src, src_len, dst, dst_len);
}

TEE_Result tee_svc_cryp_derive_key(uint32_t state, const TEE_Attribute *params,
				   uint32_t param_count, uint32_t derived_key)
{
	TEE_Result res;
	struct tee_ta_session *sess;
	struct tee_obj *ko;
	struct tee_obj *so;
	struct tee_cryp_state *cs;
	struct tee_cryp_obj_secret *sk;
	const struct tee_cryp_obj_type_props *type_props;
	struct bignum *publicvalue;
	struct bignum *sharedsecret;
	struct dh_keypair_s *tee_dh_key;

	res = tee_ta_get_current_session(&sess);
	if (res != TEE_SUCCESS)
		return res;

	res = tee_svc_cryp_get_state(sess, state, &cs);
	if (res != TEE_SUCCESS)
		return res;

	if ((param_count != 1) ||
	    (params[0].attributeID != TEE_ATTR_DH_PUBLIC_VALUE))
		return TEE_ERROR_BAD_PARAMETERS;

	/* get key set in operation */
	res = tee_obj_get(sess->ctx, cs->key1, &ko);
	if (res != TEE_SUCCESS)
		return res;

	tee_dh_key = (struct dh_keypair_s *)ko->data;

	res = tee_obj_get(sess->ctx, derived_key, &so);
	if (res != TEE_SUCCESS)
		return res;

	/* find information needed about the object to initialize */
	sk = (struct tee_cryp_obj_secret *)so->data;

	/* Find description of object */
	type_props = tee_svc_find_type_props(so->info.objectType);
	if (type_props == NULL)
		return TEE_ERROR_NOT_SUPPORTED;

	/* extract information from the attributes passed to the function */
	publicvalue = crypto_ops.bignum.allocate();
	sharedsecret = crypto_ops.bignum.allocate();
	if (publicvalue == NULL || sharedsecret == NULL)
		return TEE_ERROR_OUT_OF_MEMORY;
	crypto_ops.bignum.bin2bn(params[0].content.ref.buffer,
				 params[0].content.ref.length,
				 publicvalue);
	res = crypto_ops.derive.dh_shared_secret(tee_dh_key, publicvalue, sharedsecret);
	if (res == TEE_SUCCESS) {
		sk->key_size = crypto_ops.bignum.bin_size_for(sharedsecret);
		crypto_ops.bignum.bn2bin(sharedsecret, (uint8_t *)(sk + 1));
		so->info.handleFlags |= TEE_HANDLE_FLAG_INITIALIZED;
		SET_ATTRIBUTE(so, type_props, TEE_ATTR_SECRET_VALUE);
	}
	return res;
}

TEE_Result get_rng_array(void *buffer, int len)
{
	char *buf_char = buffer;
	int i;


	if (buf_char == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	for (i = 0; i < len; i++)
		buf_char[i] = hw_get_random_byte();

	return TEE_SUCCESS;
}

TEE_Result tee_svc_cryp_random_number_generate(void *buf, size_t blen)
{
	TEE_Result res;
	struct tee_ta_session *sess;

	res = tee_ta_get_current_session(&sess);
	if (res != TEE_SUCCESS)
		return res;

	res = tee_mmu_check_access_rights(sess->ctx,
					  TEE_MEMORY_ACCESS_WRITE |
					  TEE_MEMORY_ACCESS_ANY_OWNER,
					  (tee_uaddr_t)buf, blen);
	if (res != TEE_SUCCESS)
		return res;

	res = get_rng_array(buf, blen);
	if (res != TEE_SUCCESS)
		return res;

	return res;
}

TEE_Result tee_svc_authenc_init(uint32_t state, const void *nonce,
				size_t nonce_len, size_t tag_len,
				size_t aad_len, size_t payload_len)
{
	TEE_Result res;
	struct tee_cryp_state *cs;
	struct tee_ta_session *sess;
	struct tee_obj *o;
	struct tee_cryp_obj_secret *key;

	res = tee_ta_get_current_session(&sess);
	if (res != TEE_SUCCESS)
		return res;

	res = tee_svc_cryp_get_state(sess, state, &cs);
	if (res != TEE_SUCCESS)
		return res;

	res = tee_obj_get(sess->ctx, cs->key1, &o);
	if (res != TEE_SUCCESS)
		return res;
	if ((o->info.handleFlags & TEE_HANDLE_FLAG_INITIALIZED) == 0)
		return TEE_ERROR_BAD_PARAMETERS;

	key = (struct tee_cryp_obj_secret *)o->data;
	res = crypto_ops.authenc.init(cs->ctx, cs->algo, (uint8_t *)(key + 1),
				      key->key_size, nonce, nonce_len, tag_len,
				      aad_len, payload_len);
	if (res != TEE_SUCCESS)
		return res;

	cs->ctx_finalize = (tee_cryp_ctx_finalize_func_t)crypto_ops.authenc.final;
	return TEE_SUCCESS;
}

TEE_Result tee_svc_authenc_update_aad(uint32_t state, const void *aad_data,
				      size_t aad_data_len)
{
	TEE_Result res;
	struct tee_cryp_state *cs;
	struct tee_ta_session *sess;

	res = tee_ta_get_current_session(&sess);
	if (res != TEE_SUCCESS)
		return res;

	res = tee_mmu_check_access_rights(sess->ctx,
					  TEE_MEMORY_ACCESS_READ |
					  TEE_MEMORY_ACCESS_ANY_OWNER,
					  (tee_uaddr_t) aad_data, aad_data_len);
	if (res != TEE_SUCCESS)
		return res;

	res = tee_svc_cryp_get_state(sess, state, &cs);
	if (res != TEE_SUCCESS)
		return res;

	res = crypto_ops.authenc.update_aad(cs->ctx, cs->algo, aad_data,
					    aad_data_len);
	if (res != TEE_SUCCESS)
		return res;

	return TEE_SUCCESS;
}

TEE_Result tee_svc_authenc_update_payload(uint32_t state, const void *src_data,
					  size_t src_len, void *dst_data,
					  size_t *dst_len)
{
	TEE_Result res;
	struct tee_cryp_state *cs;
	struct tee_ta_session *sess;
	size_t dlen;

	res = tee_ta_get_current_session(&sess);
	if (res != TEE_SUCCESS)
		return res;

	res = tee_svc_cryp_get_state(sess, state, &cs);
	if (res != TEE_SUCCESS)
		return res;

	res = tee_mmu_check_access_rights(sess->ctx,
					  TEE_MEMORY_ACCESS_READ |
					  TEE_MEMORY_ACCESS_ANY_OWNER,
					  (tee_uaddr_t) src_data, src_len);
	if (res != TEE_SUCCESS)
		return res;

	res = tee_svc_copy_from_user(sess, &dlen, dst_len, sizeof(size_t));
	if (res != TEE_SUCCESS)
		return res;

	res = tee_mmu_check_access_rights(sess->ctx,
					  TEE_MEMORY_ACCESS_READ |
					  TEE_MEMORY_ACCESS_WRITE |
					  TEE_MEMORY_ACCESS_ANY_OWNER,
					  (tee_uaddr_t)dst_data, dlen);
	if (res != TEE_SUCCESS)
		return res;

	if (dlen < src_len) {
		res = TEE_ERROR_SHORT_BUFFER;
		goto out;
	}

	res = crypto_ops.authenc.update_payload(cs->ctx, cs->algo, cs->mode,
						src_data, src_len, dst_data);

out:
	if (res == TEE_SUCCESS || res == TEE_ERROR_SHORT_BUFFER) {
		TEE_Result res2 = tee_svc_copy_to_user(sess, dst_len, &src_len,
						       sizeof(size_t));
		if (res2 != TEE_SUCCESS)
			res = res2;
	}

	return res;
}

TEE_Result tee_svc_authenc_enc_final(uint32_t state, const void *src_data,
				     size_t src_len, void *dst_data,
				     size_t *dst_len, void *tag,
				     size_t *tag_len)
{
	TEE_Result res;
	struct tee_cryp_state *cs;
	struct tee_ta_session *sess;
	size_t dlen;
	size_t tlen;

	res = tee_ta_get_current_session(&sess);
	if (res != TEE_SUCCESS)
		return res;

	res = tee_svc_cryp_get_state(sess, state, &cs);
	if (res != TEE_SUCCESS)
		return res;

	if (cs->mode != TEE_MODE_ENCRYPT)
		return TEE_ERROR_BAD_PARAMETERS;

	res = tee_mmu_check_access_rights(sess->ctx,
					  TEE_MEMORY_ACCESS_READ |
					  TEE_MEMORY_ACCESS_ANY_OWNER,
					  (tee_uaddr_t)src_data, src_len);
	if (res != TEE_SUCCESS)
		return res;

	if (dst_len == NULL) {
		dlen = 0;
	} else {
		res =
		    tee_svc_copy_from_user(sess, &dlen, dst_len,
					   sizeof(size_t));
		if (res != TEE_SUCCESS)
			return res;

		res = tee_mmu_check_access_rights(sess->ctx,
						  TEE_MEMORY_ACCESS_READ |
						  TEE_MEMORY_ACCESS_WRITE |
						  TEE_MEMORY_ACCESS_ANY_OWNER,
						  (tee_uaddr_t)dst_data, dlen);
		if (res != TEE_SUCCESS)
			return res;
	}

	if (dlen < src_len) {
		res = TEE_ERROR_SHORT_BUFFER;
		goto out;
	}

	res = tee_svc_copy_from_user(sess, &tlen, tag_len, sizeof(size_t));
	if (res != TEE_SUCCESS)
		return res;

	res = tee_mmu_check_access_rights(sess->ctx,
					  TEE_MEMORY_ACCESS_READ |
					  TEE_MEMORY_ACCESS_WRITE |
					  TEE_MEMORY_ACCESS_ANY_OWNER,
					  (tee_uaddr_t)tag, tlen);
	if (res != TEE_SUCCESS)
		return res;

	res = crypto_ops.authenc.enc_final(cs->ctx, cs->algo, src_data,
					   src_len, dst_data, tag, &tlen);

out:
	if (res == TEE_SUCCESS || res == TEE_ERROR_SHORT_BUFFER) {
		TEE_Result res2;

		if (dst_len != NULL) {
			res2 = tee_svc_copy_to_user(sess, dst_len, &src_len,
						    sizeof(size_t));
			if (res2 != TEE_SUCCESS)
				return res2;
		}

		res2 =
		    tee_svc_copy_to_user(sess, tag_len, &tlen, sizeof(size_t));
		if (res2 != TEE_SUCCESS)
			return res2;
	}

	return res;
}

TEE_Result tee_svc_authenc_dec_final(uint32_t state, const void *src_data,
				     size_t src_len, void *dst_data,
				     size_t *dst_len, const void *tag,
				     size_t tag_len)
{
	TEE_Result res;
	struct tee_cryp_state *cs;
	struct tee_ta_session *sess;
	size_t dlen;

	res = tee_ta_get_current_session(&sess);
	if (res != TEE_SUCCESS)
		return res;

	res = tee_svc_cryp_get_state(sess, state, &cs);
	if (res != TEE_SUCCESS)
		return res;

	if (cs->mode != TEE_MODE_DECRYPT)
		return TEE_ERROR_BAD_PARAMETERS;

	res = tee_mmu_check_access_rights(sess->ctx,
					  TEE_MEMORY_ACCESS_READ |
					  TEE_MEMORY_ACCESS_ANY_OWNER,
					  (tee_uaddr_t)src_data, src_len);
	if (res != TEE_SUCCESS)
		return res;

	if (dst_len == NULL) {
		dlen = 0;
	} else {
		res =
		    tee_svc_copy_from_user(sess, &dlen, dst_len,
					   sizeof(size_t));
		if (res != TEE_SUCCESS)
			return res;

		res = tee_mmu_check_access_rights(sess->ctx,
						  TEE_MEMORY_ACCESS_READ |
						  TEE_MEMORY_ACCESS_WRITE |
						  TEE_MEMORY_ACCESS_ANY_OWNER,
						  (tee_uaddr_t)dst_data, dlen);
		if (res != TEE_SUCCESS)
			return res;
	}

	if (dlen < src_len) {
		res = TEE_ERROR_SHORT_BUFFER;
		goto out;
	}

	res = tee_mmu_check_access_rights(sess->ctx,
					  TEE_MEMORY_ACCESS_READ |
					  TEE_MEMORY_ACCESS_ANY_OWNER,
					  (tee_uaddr_t)tag, tag_len);
	if (res != TEE_SUCCESS)
		return res;

	res = crypto_ops.authenc.dec_final(cs->ctx, cs->algo, src_data,
					   src_len, dst_data, tag, tag_len);

out:
	if ((res == TEE_SUCCESS || res == TEE_ERROR_SHORT_BUFFER) &&
	    dst_len != NULL) {
		TEE_Result res2;

		res2 =
		    tee_svc_copy_to_user(sess, dst_len, &src_len,
					 sizeof(size_t));
		if (res2 != TEE_SUCCESS)
			return res2;
	}

	return res;
}

static void tee_svc_asymm_pkcs1_get_salt_len(const TEE_Attribute *params,
					     uint32_t num_params, int *salt_len)
{
	size_t n;

	for (n = 0; n < num_params; n++) {
		if (params[n].attributeID == TEE_ATTR_RSA_PSS_SALT_LENGTH) {
			*salt_len = params[n].content.value.a;
			return;
		}
	}
	*salt_len = -1;
}

TEE_Result tee_svc_asymm_operate(uint32_t state, const TEE_Attribute *params,
				 uint32_t num_params, const void *src_data,
				 size_t src_len, void *dst_data,
				 size_t *dst_len)
{
	TEE_Result res;
	struct tee_cryp_state *cs;
	struct tee_ta_session *sess;
	size_t dlen;
	struct tee_obj *o;
	struct rsa_public_key_s *tee_rsa_public_key;
	struct rsa_keypair_s *tee_rsa_key_pair;
	struct dsa_keypair_s *tee_dsa_key;
	void *label = NULL;
	size_t label_len = 0;
	size_t n;
	int salt_len;

	res = tee_ta_get_current_session(&sess);
	if (res != TEE_SUCCESS)
		return res;

	res = tee_svc_cryp_get_state(sess, state, &cs);
	if (res != TEE_SUCCESS)
		return res;

	res = tee_mmu_check_access_rights(
		sess->ctx,
		TEE_MEMORY_ACCESS_READ | TEE_MEMORY_ACCESS_ANY_OWNER,
		(tee_uaddr_t) src_data, src_len);
	if (res != TEE_SUCCESS)
		return res;

	res = tee_svc_copy_from_user(sess, &dlen, dst_len, sizeof(size_t));
	if (res != TEE_SUCCESS)
		return res;

	res = tee_mmu_check_access_rights(
		sess->ctx,
		TEE_MEMORY_ACCESS_READ | TEE_MEMORY_ACCESS_WRITE |
			TEE_MEMORY_ACCESS_ANY_OWNER,
		(tee_uaddr_t) dst_data, dlen);
	if (res != TEE_SUCCESS)
		return res;

	res = tee_obj_get(sess->ctx, cs->key1, &o);
	if (res != TEE_SUCCESS)
		return res;
	if ((o->info.handleFlags & TEE_HANDLE_FLAG_INITIALIZED) == 0)
		return TEE_ERROR_BAD_PARAMETERS;

	switch (cs->algo) {
	case TEE_ALG_RSA_NOPAD:
		if (cs->mode == TEE_MODE_ENCRYPT) {
			tee_rsa_public_key = o->data;
			crypto_ops.acipher.rsanopad_encrypt(tee_rsa_public_key,
							    src_data, src_len,
							    dst_data, dst_len);
		} else if (cs->mode == TEE_MODE_DECRYPT) {
			tee_rsa_key_pair = o->data;
			crypto_ops.acipher.rsanopad_decrypt(tee_rsa_key_pair,
							    src_data, src_len,
							    dst_data, dst_len);
		} else {
			res = TEE_ERROR_BAD_PARAMETERS;
		}
		break;

	case TEE_ALG_RSAES_PKCS1_V1_5:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA224:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA384:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA512:
		for (n = 0; n < num_params; n++) {
			if (params[n].attributeID == TEE_ATTR_RSA_OAEP_LABEL) {
				label = params[n].content.ref.buffer;
				label_len = params[n].content.ref.length;
				break;
			}
		}

		if (cs->mode == TEE_MODE_ENCRYPT) {
			tee_rsa_public_key = o->data;
			res = crypto_ops.acipher.rsaes_encrypt(
				cs->algo, tee_rsa_public_key, label, label_len,
				src_data, src_len, dst_data, &dlen);
		} else if (cs->mode == TEE_MODE_DECRYPT) {
			tee_rsa_key_pair = o->data;
			res = crypto_ops.acipher.rsaes_decrypt(
				cs->algo, tee_rsa_key_pair,
				label, label_len,
				src_data, src_len, dst_data, &dlen);
		} else {
			res = TEE_ERROR_BAD_PARAMETERS;
		}
		break;

	case TEE_ALG_RSASSA_PKCS1_V1_5_MD5:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA1:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA224:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA256:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA384:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA512:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512:
		if (cs->mode != TEE_MODE_SIGN) {
			res = TEE_ERROR_BAD_PARAMETERS;
			break;
		}
		tee_svc_asymm_pkcs1_get_salt_len(params, num_params, &salt_len);

		tee_rsa_key_pair = o->data;
		res = crypto_ops.acipher.rsassa_sign(cs->algo,
							 tee_rsa_key_pair,
							 salt_len, src_data,
							 src_len, dst_data,
							 &dlen);
		break;

	case TEE_ALG_DSA_SHA1:
		tee_dsa_key = o->data;
		res = crypto_ops.acipher.dsa_sign(cs->algo,
						      tee_dsa_key, src_data,
						      src_len, dst_data,
						      &dlen);
		break;

	default:
		res = TEE_ERROR_BAD_PARAMETERS;
		break;
	}

	if (res == TEE_SUCCESS || res == TEE_ERROR_SHORT_BUFFER) {
		TEE_Result res2;

		res2 =
		    tee_svc_copy_to_user(sess, dst_len, &dlen, sizeof(size_t));
		if (res2 != TEE_SUCCESS)
			return res2;
	}

	return res;
}

TEE_Result tee_svc_asymm_verify(uint32_t state, const TEE_Attribute *params,
				uint32_t num_params, const void *data,
				size_t data_len, const void *sig,
				size_t sig_len)
{
	TEE_Result res;
	struct tee_cryp_state *cs;
	struct tee_ta_session *sess;
	struct tee_obj *o;
	size_t hash_size;
	struct rsa_public_key_s *tee_rsa_key;
	int salt_len;
	struct dsa_public_key_s *tee_dsa_key;

	res = tee_ta_get_current_session(&sess);
	if (res != TEE_SUCCESS)
		return res;

	res = tee_svc_cryp_get_state(sess, state, &cs);
	if (res != TEE_SUCCESS)
		return res;

	if (cs->mode != TEE_MODE_VERIFY)
		return TEE_ERROR_BAD_PARAMETERS;

	res = tee_mmu_check_access_rights(sess->ctx,
					  TEE_MEMORY_ACCESS_READ |
					  TEE_MEMORY_ACCESS_ANY_OWNER,
					  (tee_uaddr_t)data, data_len);
	if (res != TEE_SUCCESS)
		return res;

	res = tee_mmu_check_access_rights(sess->ctx,
					  TEE_MEMORY_ACCESS_READ |
					  TEE_MEMORY_ACCESS_ANY_OWNER,
					  (tee_uaddr_t)sig, sig_len);
	if (res != TEE_SUCCESS)
		return res;

	res = tee_obj_get(sess->ctx, cs->key1, &o);
	if (res != TEE_SUCCESS)
		return res;
	if ((o->info.handleFlags & TEE_HANDLE_FLAG_INITIALIZED) == 0)
		return TEE_ERROR_BAD_PARAMETERS;

	res = crypto_ops.hash.get_digest_size(TEE_DIGEST_HASH_TO_ALGO(cs->algo),
					      &hash_size);
	if (res != TEE_SUCCESS)
		return res;

	if (data_len != hash_size)
		return TEE_ERROR_BAD_PARAMETERS;

	switch (TEE_ALG_GET_MAIN_ALG(cs->algo)) {
	case TEE_MAIN_ALGO_RSA:
		tee_rsa_key = o->data;
		tee_svc_asymm_pkcs1_get_salt_len(params, num_params, &salt_len);
		res = crypto_ops.acipher.rsassa_verify(cs->algo, tee_rsa_key,
							   salt_len, data,
							   data_len, sig, sig_len);
		break;

	case TEE_MAIN_ALGO_DSA:
		tee_dsa_key = o->data;
		res = crypto_ops.acipher.dsa_verify(cs->algo, tee_dsa_key,
							data, data_len, sig,
							sig_len);
		break;

	default:
		res = TEE_ERROR_NOT_SUPPORTED;
	}

	return res;
}

TEE_Result tee_cryp_init(void)
{
	if (crypto_ops.init)
		return crypto_ops.init();

	return TEE_SUCCESS;
}
