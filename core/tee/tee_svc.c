// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * Copyright (c) 2020, Linaro Limited
 */

#include <compiler.h>
#include <kernel/chip_services.h>
#include <kernel/pseudo_ta.h>
#include <kernel/tee_common.h>
#include <kernel/tee_common_otp.h>
#include <kernel/tee_ta_manager.h>
#include <kernel/tee_time.h>
#include <kernel/trace_ta.h>
#include <kernel/user_access.h>
#include <mm/core_memprot.h>
#include <mm/mobj.h>
#include <mm/tee_mm.h>
#include <mm/vm.h>
#include <stdlib_ext.h>
#include <tee_api_types.h>
#include <tee/tee_cryp_utl.h>
#include <tee/tee_svc.h>
#include <trace.h>
#include <user_ta_header.h>
#include <utee_types.h>
#include <util.h>

vaddr_t tee_svc_uref_base;

void syscall_log(const void *buf __maybe_unused, size_t len __maybe_unused)
{
#ifdef CFG_TEE_CORE_TA_TRACE
	char *kbuf;

	if (len == 0)
		return;

	kbuf = malloc(len + 1);
	if (kbuf == NULL)
		return;

	if (copy_from_user(kbuf, buf, len) == TEE_SUCCESS) {
		kbuf[len] = '\0';
		trace_ext_puts(kbuf);
	}

	free_wipe(kbuf);
#endif
}

TEE_Result syscall_not_supported(void)
{
	return TEE_ERROR_NOT_SUPPORTED;
}

/* Configuration properties */
/* API implementation version */
static const char api_vers[] = TO_STR(CFG_TEE_API_VERSION);

/* Implementation description (implementation-dependent) */
static const char descr[] = TO_STR(CFG_TEE_IMPL_DESCR);

/*
 * TA persistent time protection level
 * 100: Persistent time based on an REE-controlled real-time clock
 * and on the TEE Trusted Storage for the storage of origins (default).
 * 1000: Persistent time based on a TEE-controlled real-time clock
 * and the TEE Trusted Storage.
 * The real-time clock MUST be out of reach of software attacks
 * from the REE.
 */
static const uint32_t ta_time_prot_lvl = 100;

/* Elliptic Curve Cryptographic support */
#ifdef CFG_CRYPTO_ECC
static const bool crypto_ecc_en = 1;
#else
static const bool crypto_ecc_en;
#endif

/*
 * Trusted storage anti rollback protection level
 * 0 (or missing): No antirollback protection (default)
 * 100: Antirollback enforced at REE level
 * 1000: Antirollback TEE-controlled hardware
 */
#ifdef CFG_RPMB_FS
static const uint32_t ts_antiroll_prot_lvl = 1000;
#else
static const uint32_t ts_antiroll_prot_lvl;
#endif

/* Trusted OS implementation version */
static const char trustedos_impl_version[] = TO_STR(TEE_IMPL_VERSION);

/* Trusted OS implementation version (binary value) */
static const uint32_t trustedos_impl_bin_version; /* 0 by default */

/* Trusted OS implementation manufacturer name */
static const char trustedos_manufacturer[] = TO_STR(CFG_TEE_MANUFACTURER);

/* Trusted firmware version */
static const char fw_impl_version[] = TO_STR(CFG_TEE_FW_IMPL_VERSION);

/* Trusted firmware version (binary value) */
static const uint32_t fw_impl_bin_version; /* 0 by default */

/* Trusted firmware manufacturer name */
static const char fw_manufacturer[] = TO_STR(CFG_TEE_FW_MANUFACTURER);

static TEE_Result get_prop_tee_dev_id(struct ts_session *sess __unused,
				      void *buf, size_t *blen)
{
	TEE_Result res;
	TEE_UUID uuid;
	const size_t nslen = 5;
	uint8_t data[5 + FVR_DIE_ID_NUM_REGS * sizeof(uint32_t)] = {
	    'O', 'P', 'T', 'E', 'E' };

	if (*blen < sizeof(uuid)) {
		*blen = sizeof(uuid);
		return TEE_ERROR_SHORT_BUFFER;
	}
	*blen = sizeof(uuid);

	if (tee_otp_get_die_id(data + nslen, sizeof(data) - nslen))
		return TEE_ERROR_BAD_STATE;

	res = tee_hash_createdigest(TEE_ALG_SHA256, data, sizeof(data),
				    (uint8_t *)&uuid, sizeof(uuid));
	if (res != TEE_SUCCESS)
		return TEE_ERROR_BAD_STATE;

	/*
	 * Changes the random value into and UUID as specifiec
	 * in RFC 4122. The magic values are from the example
	 * code in the RFC.
	 *
	 * TEE_UUID is defined slightly different from the RFC,
	 * but close enough for our purpose.
	 */

	uuid.timeHiAndVersion &= 0x0fff;
	uuid.timeHiAndVersion |= 5 << 12;

	/* uuid.clock_seq_hi_and_reserved in the RFC */
	uuid.clockSeqAndNode[0] &= 0x3f;
	uuid.clockSeqAndNode[0] |= 0x80;

	return copy_to_user(buf, &uuid, sizeof(TEE_UUID));
}

static TEE_Result
get_prop_tee_sys_time_prot_level(struct ts_session *sess __unused,
				 void *buf, size_t *blen)
{
	uint32_t prot;

	if (*blen < sizeof(prot)) {
		*blen = sizeof(prot);
		return TEE_ERROR_SHORT_BUFFER;
	}
	*blen = sizeof(prot);
	prot = tee_time_get_sys_time_protection_level();
	return copy_to_user(buf, &prot, sizeof(prot));
}

static TEE_Result get_prop_client_id(struct ts_session *sess,
				     void *buf, size_t *blen)
{
	if (*blen < sizeof(TEE_Identity)) {
		*blen = sizeof(TEE_Identity);
		return TEE_ERROR_SHORT_BUFFER;
	}
	*blen = sizeof(TEE_Identity);
	return copy_to_user(buf, &to_ta_session(sess)->clnt_id,
			    sizeof(TEE_Identity));
}

static TEE_Result get_prop_ta_app_id(struct ts_session *sess,
				     void *buf, size_t *blen)
{
	if (*blen < sizeof(TEE_UUID)) {
		*blen = sizeof(TEE_UUID);
		return TEE_ERROR_SHORT_BUFFER;
	}
	*blen = sizeof(TEE_UUID);
	return copy_to_user(buf, &sess->ctx->uuid, sizeof(TEE_UUID));
}

/* Properties of the set TEE_PROPSET_CURRENT_CLIENT */
const struct tee_props tee_propset_client[] = {
	{
		.name = "gpd.client.identity",
		.prop_type = USER_TA_PROP_TYPE_IDENTITY,
		.get_prop_func = get_prop_client_id
	},
};

/* Properties of the set TEE_PROPSET_CURRENT_TA */
const struct tee_props tee_propset_ta[] = {
	{
		.name = "gpd.ta.appID",
		.prop_type = USER_TA_PROP_TYPE_UUID,
		.get_prop_func = get_prop_ta_app_id
	},

	/*
	 * Following properties are processed directly in libutee:
	 *	TA_PROP_STR_SINGLE_INSTANCE
	 *	TA_PROP_STR_MULTI_SESSION
	 *	TA_PROP_STR_KEEP_ALIVE
	 *	TA_PROP_STR_DATA_SIZE
	 *	TA_PROP_STR_STACK_SIZE
	 *	TA_PROP_STR_VERSION
	 *	TA_PROP_STR_DESCRIPTION
	 *	USER_TA_PROP_TYPE_STRING,
	 *	TA_DESCRIPTION
	 */
};

/* Properties of the set TEE_PROPSET_TEE_IMPLEMENTATION */
const struct tee_props tee_propset_tee[] = {
	{
		.name = "gpd.tee.apiversion",
		.prop_type = USER_TA_PROP_TYPE_STRING,
		.data = api_vers,
		.len = sizeof(api_vers),
	},
	{
		.name = "gpd.tee.description",
		.prop_type = USER_TA_PROP_TYPE_STRING,
		.data = descr, .len = sizeof(descr)
	},
	{
		.name = "gpd.tee.deviceID",
		.prop_type = USER_TA_PROP_TYPE_UUID,
		.get_prop_func = get_prop_tee_dev_id
	},
	{
		.name = "gpd.tee.systemTime.protectionLevel",
		.prop_type = USER_TA_PROP_TYPE_U32,
		.get_prop_func = get_prop_tee_sys_time_prot_level
	},
	{
		.name = "gpd.tee.TAPersistentTime.protectionLevel",
		.prop_type = USER_TA_PROP_TYPE_U32,
		.data = &ta_time_prot_lvl,
		.len = sizeof(ta_time_prot_lvl)
	},
	{
		.name = "gpd.tee.cryptography.ecc",
		.prop_type = USER_TA_PROP_TYPE_BOOL,
		.data = &crypto_ecc_en,
		.len = sizeof(crypto_ecc_en)
	},
	{
		.name = "gpd.tee.trustedStorage.antiRollback.protectionLevel",
		.prop_type = USER_TA_PROP_TYPE_U32,
		.data = &ts_antiroll_prot_lvl,
		.len = sizeof(ts_antiroll_prot_lvl)
	},
	{
		.name = "gpd.tee.trustedos.implementation.version",
		.prop_type = USER_TA_PROP_TYPE_STRING,
		.data = trustedos_impl_version,
		.len = sizeof(trustedos_impl_version)
	},
	{
		.name = "gpd.tee.trustedos.implementation.binaryversion",
		.prop_type = USER_TA_PROP_TYPE_U32,
		.data = &trustedos_impl_bin_version,
		.len = sizeof(trustedos_impl_bin_version)
	},
	{
		.name = "gpd.tee.trustedos.manufacturer",
		.prop_type = USER_TA_PROP_TYPE_STRING,
		.data = trustedos_manufacturer,
		.len = sizeof(trustedos_manufacturer)
	},
	{
		.name = "gpd.tee.firmware.implementation.version",
		.prop_type = USER_TA_PROP_TYPE_STRING,
		.data = fw_impl_version,
		.len = sizeof(fw_impl_version)
	},
	{
		.name = "gpd.tee.firmware.implementation.binaryversion",
		.prop_type = USER_TA_PROP_TYPE_U32,
		.data = &fw_impl_bin_version,
		.len = sizeof(fw_impl_bin_version)
	},
	{
		.name = "gpd.tee.firmware.manufacturer",
		.prop_type = USER_TA_PROP_TYPE_STRING,
		.data = fw_manufacturer,
		.len = sizeof(fw_manufacturer)
	},

	/*
	 * Following properties are processed directly in libutee:
	 *	gpd.tee.arith.maxBigIntSize
	 */
};

__weak const struct tee_vendor_props vendor_props_client;
__weak const struct tee_vendor_props vendor_props_ta;
__weak const struct tee_vendor_props vendor_props_tee;

static void get_prop_set(unsigned long prop_set,
			 const struct tee_props **props,
			 size_t *size,
			 const struct tee_props **vendor_props,
			 size_t *vendor_size)
{
	if ((TEE_PropSetHandle)prop_set == TEE_PROPSET_CURRENT_CLIENT) {
		*props = tee_propset_client;
		*size = ARRAY_SIZE(tee_propset_client);
		*vendor_props = vendor_props_client.props;
		*vendor_size = vendor_props_client.len;
	} else if ((TEE_PropSetHandle)prop_set == TEE_PROPSET_CURRENT_TA) {
		*props = tee_propset_ta;
		*size = ARRAY_SIZE(tee_propset_ta);
		*vendor_props = vendor_props_ta.props;
		*vendor_size = vendor_props_ta.len;
	} else if ((TEE_PropSetHandle)prop_set ==
		   TEE_PROPSET_TEE_IMPLEMENTATION) {
		*props = tee_propset_tee;
		*size = ARRAY_SIZE(tee_propset_tee);
		*vendor_props = vendor_props_tee.props;
		*vendor_size = vendor_props_tee.len;
	} else {
		*props = NULL;
		*size = 0;
		*vendor_props = NULL;
		*vendor_size = 0;
	}
}

static const struct tee_props *get_prop_struct(unsigned long prop_set,
					       unsigned long index)
{
	const struct tee_props *props;
	const struct tee_props *vendor_props;
	size_t size;
	size_t vendor_size;

	get_prop_set(prop_set, &props, &size, &vendor_props, &vendor_size);

	if (index < size)
		return &(props[index]);
	index -= size;

	if (index < vendor_size)
		return &(vendor_props[index]);

	return NULL;
}

/*
 * prop_set is part of TEE_PROPSET_xxx
 * index is the index in the Property Set to retrieve
 * if name is not NULL, the name of "index" property is returned
 * if buf is not NULL, the property is returned
 */
TEE_Result syscall_get_property(unsigned long prop_set,
				unsigned long index,
				void *name, uint32_t *name_len,
				void *buf, uint32_t *blen,
				uint32_t *prop_type)
{
	struct ts_session *sess = ts_get_current_session();
	TEE_Result res = TEE_SUCCESS;
	TEE_Result res2 = TEE_SUCCESS;
	const struct tee_props *prop = NULL;
	uint32_t klen = 0;
	size_t klen_size = 0;
	uint32_t elen = 0;

	prop = get_prop_struct(prop_set, index);
	if (!prop)
		return TEE_ERROR_ITEM_NOT_FOUND;

	/* Get the property type */
	if (prop_type) {
		res = copy_to_user(prop_type, &prop->prop_type,
				   sizeof(*prop_type));
		if (res != TEE_SUCCESS)
			return res;
	}

	/* Get the property */
	if (buf && blen) {
		res = copy_from_user(&klen, blen, sizeof(klen));
		if (res != TEE_SUCCESS)
			return res;

		if (prop->get_prop_func) {
			klen_size = klen;
			res = prop->get_prop_func(sess, buf, &klen_size);
			klen = klen_size;
			res2 = copy_to_user(blen, &klen, sizeof(*blen));
		} else {
			if (klen < prop->len)
				res = TEE_ERROR_SHORT_BUFFER;
			else
				res = copy_to_user(buf, prop->data, prop->len);
			res2 = copy_to_user(blen, &prop->len, sizeof(*blen));
		}
		if (res2 != TEE_SUCCESS)
			return res2;
		if (res != TEE_SUCCESS)
			return res;
	}

	/* Get the property name */
	if (name && name_len) {
		res = copy_from_user(&klen, name_len, sizeof(klen));
		if (res != TEE_SUCCESS)
			return res;

		elen = strlen(prop->name) + 1;

		if (klen < elen)
			res = TEE_ERROR_SHORT_BUFFER;
		else
			res = copy_to_user(name, prop->name, elen);
		res2 = copy_to_user(name_len, &elen, sizeof(*name_len));
		if (res2 != TEE_SUCCESS)
			return res2;
		if (res != TEE_SUCCESS)
			return res;
	}

	return res;
}

/*
 * prop_set is part of TEE_PROPSET_xxx
 */
TEE_Result syscall_get_property_name_to_index(unsigned long prop_set,
					      void *name,
					      unsigned long name_len,
					      uint32_t *index)
{
	TEE_Result res = TEE_SUCCESS;
	const struct tee_props *props = NULL;
	size_t size = 0;
	const struct tee_props *vendor_props = NULL;
	size_t vendor_size = 0;
	char *kname = NULL;
	uint32_t i = 0;

	get_prop_set(prop_set, &props, &size, &vendor_props, &vendor_size);
	if (!props)
		return TEE_ERROR_ITEM_NOT_FOUND;

	if (!name || !name_len) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	kname = malloc(name_len);
	if (!kname)
		return TEE_ERROR_OUT_OF_MEMORY;
	res = copy_from_user(kname, name, name_len);
	if (res != TEE_SUCCESS)
		goto out;
	kname[name_len - 1] = 0;

	res = TEE_ERROR_ITEM_NOT_FOUND;
	for (i = 0; i < size; i++) {
		if (!strcmp(kname, props[i].name)) {
			res = copy_to_user(index, &i, sizeof(*index));
			goto out;
		}
	}
	for (i = size; i < size + vendor_size; i++) {
		if (!strcmp(kname, vendor_props[i - size].name)) {
			res = copy_to_user(index, &i, sizeof(*index));
			goto out;
		}
	}

out:
	free_wipe(kname);
	return res;
}

static TEE_Result utee_param_to_param(struct user_ta_ctx *utc,
				      struct tee_ta_param *p,
				      struct utee_params *up)
{
	size_t n = 0;
	uint32_t types = up->types;

	p->types = types;
	for (n = 0; n < TEE_NUM_PARAMS; n++) {
		uintptr_t a = up->vals[n * 2];
		size_t b = up->vals[n * 2 + 1];
		uint32_t flags = TEE_MEMORY_ACCESS_READ |
				 TEE_MEMORY_ACCESS_ANY_OWNER;

		switch (TEE_PARAM_TYPE_GET(types, n)) {
		case TEE_PARAM_TYPE_MEMREF_OUTPUT:
		case TEE_PARAM_TYPE_MEMREF_INOUT:
			flags |= TEE_MEMORY_ACCESS_WRITE;
			fallthrough;
		case TEE_PARAM_TYPE_MEMREF_INPUT:
			p->u[n].mem.offs = a;
			p->u[n].mem.size = b;

			if (!p->u[n].mem.offs) {
				/* Allow NULL memrefs if of size 0 */
				if (p->u[n].mem.size)
					return TEE_ERROR_BAD_PARAMETERS;
				p->u[n].mem.mobj = NULL;
				break;
			}

			p->u[n].mem.mobj = &mobj_virt;

			if (vm_check_access_rights(&utc->uctx, flags, a, b))
				return TEE_ERROR_ACCESS_DENIED;
			break;
		case TEE_PARAM_TYPE_VALUE_INPUT:
		case TEE_PARAM_TYPE_VALUE_INOUT:
			p->u[n].val.a = a;
			p->u[n].val.b = b;
			break;
		default:
			memset(&p->u[n], 0, sizeof(p->u[n]));
			break;
		}
	}

	return TEE_SUCCESS;
}

static TEE_Result alloc_temp_sec_mem(size_t size, struct mobj **mobj,
				     uint8_t **va)
{
	/* Allocate section in secure DDR */
#ifdef CFG_PAGED_USER_TA
	*mobj = mobj_seccpy_shm_alloc(size);
#else
	*mobj = mobj_mm_alloc(mobj_sec_ddr, size, &tee_mm_sec_ddr);
#endif
	if (!*mobj)
		return TEE_ERROR_GENERIC;

	*va = mobj_get_va(*mobj, 0);
	return TEE_SUCCESS;
}

/*
 * TA invokes some TA with parameter.
 * If some parameters are memory references:
 * - either the memref is inside TA private RAM: TA is not allowed to expose
 *   its private RAM: use a temporary memory buffer and copy the data.
 * - or the memref is not in the TA private RAM:
 *   - if the memref was mapped to the TA, TA is allowed to expose it.
 *   - if so, converts memref virtual address into a physical address.
 */
static TEE_Result tee_svc_copy_param(struct ts_session *sess,
				     struct ts_session *called_sess,
				     struct utee_params *callee_params,
				     struct tee_ta_param *param,
				     void *tmp_buf_va[TEE_NUM_PARAMS],
				     size_t tmp_buf_size[TEE_NUM_PARAMS],
				     struct mobj **mobj_tmp)
{
	struct user_ta_ctx *utc = to_user_ta_ctx(sess->ctx);
	bool ta_private_memref[TEE_NUM_PARAMS] = { false, };
	TEE_Result res = TEE_SUCCESS;
	size_t dst_offs = 0;
	size_t req_mem = 0;
	uint8_t *dst = 0;
	void *va = NULL;
	size_t n = 0;
	size_t s = 0;

	/* fill 'param' input struct with caller params description buffer */
	if (!callee_params) {
		memset(param, 0, sizeof(*param));
	} else {
		uint32_t flags = TEE_MEMORY_ACCESS_READ |
				 TEE_MEMORY_ACCESS_WRITE |
				 TEE_MEMORY_ACCESS_ANY_OWNER;

		res = vm_check_access_rights(&utc->uctx, flags,
					     (uaddr_t)callee_params,
					     sizeof(struct utee_params));
		if (res != TEE_SUCCESS)
			return res;
		res = utee_param_to_param(utc, param, callee_params);
		if (res != TEE_SUCCESS)
			return res;
	}

	if (called_sess && is_pseudo_ta_ctx(called_sess->ctx)) {
		/* pseudo TA borrows the mapping of the calling TA */
		return TEE_SUCCESS;
	}

	/* All mobj in param are of type MOJB_TYPE_VIRT */

	for (n = 0; n < TEE_NUM_PARAMS; n++) {

		ta_private_memref[n] = false;

		switch (TEE_PARAM_TYPE_GET(param->types, n)) {
		case TEE_PARAM_TYPE_MEMREF_INPUT:
		case TEE_PARAM_TYPE_MEMREF_OUTPUT:
		case TEE_PARAM_TYPE_MEMREF_INOUT:
			va = (void *)param->u[n].mem.offs;
			s = param->u[n].mem.size;
			if (!va) {
				if (s)
					return TEE_ERROR_BAD_PARAMETERS;
				break;
			}
			/* uTA cannot expose its private memory */
			if (vm_buf_is_inside_um_private(&utc->uctx, va, s)) {
				s = ROUNDUP(s, sizeof(uint32_t));
				if (ADD_OVERFLOW(req_mem, s, &req_mem))
					return TEE_ERROR_BAD_PARAMETERS;
				ta_private_memref[n] = true;
				break;
			}

			res = vm_buf_to_mboj_offs(&utc->uctx, va, s,
						  &param->u[n].mem.mobj,
						  &param->u[n].mem.offs);
			if (res != TEE_SUCCESS)
				return res;
			break;
		default:
			break;
		}
	}

	if (req_mem == 0)
		return TEE_SUCCESS;

	res = alloc_temp_sec_mem(req_mem, mobj_tmp, &dst);
	if (res != TEE_SUCCESS)
		return res;
	dst_offs = 0;

	for (n = 0; n < TEE_NUM_PARAMS; n++) {

		if (!ta_private_memref[n])
			continue;

		s = ROUNDUP(param->u[n].mem.size, sizeof(uint32_t));

		switch (TEE_PARAM_TYPE_GET(param->types, n)) {
		case TEE_PARAM_TYPE_MEMREF_INPUT:
		case TEE_PARAM_TYPE_MEMREF_INOUT:
			va = (void *)param->u[n].mem.offs;
			if (va) {
				res = copy_from_user(dst, va,
						     param->u[n].mem.size);
				if (res != TEE_SUCCESS)
					return res;
				param->u[n].mem.offs = dst_offs;
				param->u[n].mem.mobj = *mobj_tmp;
				tmp_buf_va[n] = dst;
				tmp_buf_size[n] = param->u[n].mem.size;
				dst += s;
				dst_offs += s;
			}
			break;

		case TEE_PARAM_TYPE_MEMREF_OUTPUT:
			va = (void *)param->u[n].mem.offs;
			if (va) {
				param->u[n].mem.offs = dst_offs;
				param->u[n].mem.mobj = *mobj_tmp;
				tmp_buf_va[n] = dst;
				tmp_buf_size[n] = param->u[n].mem.size;
				dst += s;
				dst_offs += s;
			}
			break;

		default:
			continue;
		}
	}

	return TEE_SUCCESS;
}

/*
 * Back from execution of service: update parameters passed from TA:
 * If some parameters were memory references:
 * - either the memref was temporary: copy back data and update size
 * - or it was the original TA memref: update only the size value.
 */
static TEE_Result tee_svc_update_out_param(
		struct tee_ta_param *param,
		void *tmp_buf_va[TEE_NUM_PARAMS],
		size_t tmp_buf_size[TEE_NUM_PARAMS],
		struct utee_params *usr_param)
{
	size_t n;
	uint64_t *vals = usr_param->vals;
	size_t sz = 0;

	for (n = 0; n < TEE_NUM_PARAMS; n++) {
		switch (TEE_PARAM_TYPE_GET(param->types, n)) {
		case TEE_PARAM_TYPE_MEMREF_OUTPUT:
		case TEE_PARAM_TYPE_MEMREF_INOUT:
			/*
			 * Memory copy is only needed if there's a temporary
			 * buffer involved, tmp_buf_va[n] is only update if
			 * a temporary buffer is used. Otherwise only the
			 * size needs to be updated.
			 */
			sz = param->u[n].mem.size;
			if (tmp_buf_va[n] && sz <= vals[n * 2 + 1]) {
				void *src = tmp_buf_va[n];
				void *dst = (void *)(uintptr_t)vals[n * 2];
				TEE_Result res = TEE_SUCCESS;

				/*
				 * TA is allowed to return a size larger than
				 * the original size. However, in such cases no
				 * data should be synchronized as per TEE Client
				 * API spec.
				 */
				if (sz <= tmp_buf_size[n]) {
					res = copy_to_user(dst, src, sz);
					if (res != TEE_SUCCESS)
						return res;
				}
			}
			usr_param->vals[n * 2 + 1] = sz;
			break;

		case TEE_PARAM_TYPE_VALUE_OUTPUT:
		case TEE_PARAM_TYPE_VALUE_INOUT:
			vals[n * 2] = param->u[n].val.a;
			vals[n * 2 + 1] = param->u[n].val.b;
			break;

		default:
			continue;
		}
	}

	return TEE_SUCCESS;
}

/* Called when a TA calls an OpenSession on another TA */
TEE_Result syscall_open_ta_session(const TEE_UUID *dest,
			unsigned long cancel_req_to,
			struct utee_params *usr_param, uint32_t *ta_sess,
			uint32_t *ret_orig)
{
	struct ts_session *sess = ts_get_current_session();
	struct user_ta_ctx *utc = to_user_ta_ctx(sess->ctx);
	TEE_Result res = TEE_SUCCESS;
	uint32_t ret_o = TEE_ORIGIN_TEE;
	struct tee_ta_session *s = NULL;
	struct mobj *mobj_param = NULL;
	TEE_UUID *uuid = malloc(sizeof(TEE_UUID));
	struct tee_ta_param *param = malloc(sizeof(struct tee_ta_param));
	TEE_Identity *clnt_id = malloc(sizeof(TEE_Identity));
	void *tmp_buf_va[TEE_NUM_PARAMS] = { NULL };
	size_t tmp_buf_size[TEE_NUM_PARAMS] = { 0 };

	if (uuid == NULL || param == NULL || clnt_id == NULL) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out_free_only;
	}

	memset(param, 0, sizeof(struct tee_ta_param));

	res = copy_from_user_private(uuid, dest, sizeof(TEE_UUID));
	if (res != TEE_SUCCESS)
		goto function_exit;

	clnt_id->login = TEE_LOGIN_TRUSTED_APP;
	memcpy(&clnt_id->uuid, &sess->ctx->uuid, sizeof(TEE_UUID));

	res = tee_svc_copy_param(sess, NULL, usr_param, param, tmp_buf_va,
				 tmp_buf_size, &mobj_param);
	if (res != TEE_SUCCESS)
		goto function_exit;

	res = tee_ta_open_session(&ret_o, &s, &utc->open_sessions, uuid,
				  clnt_id, cancel_req_to, param);
	vm_set_ctx(&utc->ta_ctx.ts_ctx);
	if (res != TEE_SUCCESS)
		goto function_exit;

	res = tee_svc_update_out_param(param, tmp_buf_va, tmp_buf_size,
				       usr_param);

function_exit:
	mobj_put_wipe(mobj_param);
	if (res == TEE_SUCCESS)
		copy_to_user_private(ta_sess, &s->id, sizeof(s->id));
	copy_to_user_private(ret_orig, &ret_o, sizeof(ret_o));

out_free_only:
	free_wipe(param);
	free_wipe(uuid);
	free_wipe(clnt_id);
	return res;
}

TEE_Result syscall_close_ta_session(unsigned long ta_sess)
{
	struct ts_session *sess = ts_get_current_session();
	struct user_ta_ctx *utc = to_user_ta_ctx(sess->ctx);
	TEE_Identity clnt_id = { };
	struct tee_ta_session *s = NULL;

	s = tee_ta_find_session(ta_sess, &utc->open_sessions);

	clnt_id.login = TEE_LOGIN_TRUSTED_APP;
	memcpy(&clnt_id.uuid, &sess->ctx->uuid, sizeof(TEE_UUID));

	return tee_ta_close_session(s, &utc->open_sessions, &clnt_id);
}

TEE_Result syscall_invoke_ta_command(unsigned long ta_sess,
			unsigned long cancel_req_to, unsigned long cmd_id,
			struct utee_params *usr_param, uint32_t *ret_orig)
{
	struct ts_session *sess = ts_get_current_session();
	struct user_ta_ctx *utc = to_user_ta_ctx(sess->ctx);
	TEE_Result res = TEE_SUCCESS;
	TEE_Result res2 = TEE_SUCCESS;
	uint32_t ret_o = TEE_ORIGIN_TEE;
	struct tee_ta_param param = { 0 };
	TEE_Identity clnt_id = { };
	struct tee_ta_session *called_sess = NULL;
	struct mobj *mobj_param = NULL;
	void *tmp_buf_va[TEE_NUM_PARAMS] = { NULL };
	size_t tmp_buf_size[TEE_NUM_PARAMS] = { };

	called_sess = tee_ta_get_session((uint32_t)ta_sess, true,
				&utc->open_sessions);
	if (!called_sess)
		return TEE_ERROR_BAD_PARAMETERS;

	clnt_id.login = TEE_LOGIN_TRUSTED_APP;
	memcpy(&clnt_id.uuid, &sess->ctx->uuid, sizeof(TEE_UUID));

	res = tee_svc_copy_param(sess, &called_sess->ts_sess, usr_param, &param,
				 tmp_buf_va, tmp_buf_size, &mobj_param);
	if (res != TEE_SUCCESS)
		goto function_exit;

	res = tee_ta_invoke_command(&ret_o, called_sess, &clnt_id,
				    cancel_req_to, cmd_id, &param);
	if (res == TEE_ERROR_TARGET_DEAD)
		goto function_exit;

	res2 = tee_svc_update_out_param(&param, tmp_buf_va, tmp_buf_size,
					usr_param);
	if (res2 != TEE_SUCCESS) {
		/*
		 * Spec for TEE_InvokeTACommand() says:
		 * "If the return origin is different from
		 * TEE_ORIGIN_TRUSTED_APP, then the function has failed
		 * before it could reach the destination Trusted
		 * Application."
		 *
		 * But if we can't update params to the caller we have no
		 * choice we need to return some error to indicate that
		 * parameters aren't updated as expected.
		 */
		ret_o = TEE_ORIGIN_TEE;
		res = res2;
	}

function_exit:
	tee_ta_put_session(called_sess);
	mobj_put_wipe(mobj_param);
	copy_to_user_private(ret_orig, &ret_o, sizeof(ret_o));
	return res;
}

TEE_Result syscall_check_access_rights(unsigned long flags, const void *buf,
				       size_t len)
{
	struct ts_session *s = ts_get_current_session();

	return vm_check_access_rights(&to_user_ta_ctx(s->ctx)->uctx, flags,
				      (uaddr_t)buf, len);
}

TEE_Result syscall_get_cancellation_flag(uint32_t *cancel)
{
	struct ts_session *s = ts_get_current_session();
	uint32_t c = 0;

	c = tee_ta_session_is_cancelled(to_ta_session(s), NULL);

	return copy_to_user(cancel, &c, sizeof(c));
}

TEE_Result syscall_unmask_cancellation(uint32_t *old_mask)
{
	struct ts_session *s = ts_get_current_session();
	struct tee_ta_session *sess = NULL;
	uint32_t m = 0;

	sess = to_ta_session(s);
	m = sess->cancel_mask;
	sess->cancel_mask = false;
	return copy_to_user(old_mask, &m, sizeof(m));
}

TEE_Result syscall_mask_cancellation(uint32_t *old_mask)
{
	struct ts_session *s = ts_get_current_session();
	struct tee_ta_session *sess = NULL;
	uint32_t m = 0;

	sess = to_ta_session(s);
	m = sess->cancel_mask;
	sess->cancel_mask = true;
	return copy_to_user(old_mask, &m, sizeof(m));
}

TEE_Result syscall_wait(unsigned long timeout)
{
	struct ts_session *s = ts_get_current_session();
	TEE_Result res = TEE_SUCCESS;
	uint32_t mytime = 0;
	TEE_Time base_time = { };
	TEE_Time current_time = { };

	res = tee_time_get_sys_time(&base_time);
	if (res != TEE_SUCCESS)
		return res;

	while (true) {
		res = tee_time_get_sys_time(&current_time);
		if (res != TEE_SUCCESS)
			return res;

		if (tee_ta_session_is_cancelled(to_ta_session(s),
						&current_time))
			return TEE_ERROR_CANCEL;

		mytime = (current_time.seconds - base_time.seconds) * 1000 +
		    (int)current_time.millis - (int)base_time.millis;
		if (mytime >= timeout)
			return TEE_SUCCESS;

		tee_time_wait(timeout - mytime);
	}

	return res;
}

TEE_Result syscall_get_time(unsigned long cat, TEE_Time *mytime)
{
	struct ts_session *s = ts_get_current_session();
	TEE_Result res = TEE_SUCCESS;
	TEE_Result res2 = TEE_SUCCESS;
	TEE_Time t = { };

	switch (cat) {
	case UTEE_TIME_CAT_SYSTEM:
		res = tee_time_get_sys_time(&t);
		break;
	case UTEE_TIME_CAT_TA_PERSISTENT:
		res = tee_time_get_ta_time((const void *)&s->ctx->uuid, &t);
		break;
	case UTEE_TIME_CAT_REE:
		res = tee_time_get_ree_time(&t);
		break;
	default:
		res = TEE_ERROR_BAD_PARAMETERS;
		break;
	}

	if (res == TEE_SUCCESS || res == TEE_ERROR_OVERFLOW) {
		res2 = copy_to_user_private(mytime, &t, sizeof(t));
		if (res2 != TEE_SUCCESS)
			res = res2;
	}

	return res;
}

TEE_Result syscall_set_ta_time(const TEE_Time *mytime)
{
	struct ts_session *s = ts_get_current_session();
	TEE_Result res = TEE_SUCCESS;
	TEE_Time t = { };

	res = copy_from_user_private(&t, mytime, sizeof(t));
	if (res != TEE_SUCCESS)
		return res;

	return tee_time_set_ta_time((const void *)&s->ctx->uuid, &t);
}
