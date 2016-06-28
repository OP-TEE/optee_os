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
#include <util.h>
#include <kernel/tee_common_otp.h>
#include <kernel/tee_common.h>
#include <tee_api_types.h>
#include <kernel/tee_ta_manager.h>
#include <utee_types.h>
#include <tee/tee_svc.h>
#include <tee/tee_cryp_utl.h>
#include <mm/tee_mmu.h>
#include <mm/tee_mm.h>
#include <mm/core_memprot.h>
#include <kernel/tee_time.h>

#include <user_ta_header.h>
#include <trace.h>
#include <kernel/trace_ta.h>
#include <kernel/chip_services.h>
#include <kernel/static_ta.h>

#include <assert.h>

vaddr_t tee_svc_uref_base;

void syscall_log(const void *buf __maybe_unused, size_t len __maybe_unused)
{
#ifdef CFG_TEE_CORE_TA_TRACE
	char *kbuf;

	if (len == 0)
		return;

	kbuf = malloc(len);
	if (kbuf == NULL)
		return;
	*kbuf = '\0';

	/* log as Info/Raw traces */
	if (tee_svc_copy_from_user(kbuf, buf, len) == TEE_SUCCESS)
		TAMSG_RAW("%.*s", (int)len, kbuf);

	free(kbuf);
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
static const uint32_t crypto_ecc_en = 1;
#else
static const uint32_t crypto_ecc_en;
#endif

/*
 * Trusted storage anti rollback protection level
 * 0 (or missing): No antirollback protection (default)
 * 100: Antirollback enforced at REE level
 * 1000: Antirollback TEE-controlled hardware
 */
static const uint32_t ts_antiroll_prot_lvl;

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

static TEE_Result get_prop_tee_dev_id(struct tee_ta_session *sess __unused,
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

	return tee_svc_copy_to_user(buf, &uuid, sizeof(TEE_UUID));
}

static TEE_Result get_prop_tee_sys_time_prot_level(
			struct tee_ta_session *sess __unused,
			void *buf, size_t *blen)
{
	uint32_t prot;

	if (*blen < sizeof(prot)) {
		*blen = sizeof(prot);
		return TEE_ERROR_SHORT_BUFFER;
	}
	*blen = sizeof(prot);
	prot = tee_time_get_sys_time_protection_level();
	return tee_svc_copy_to_user(buf, &prot, sizeof(prot));
}

static TEE_Result get_prop_client_id(struct tee_ta_session *sess __unused,
				     void *buf, size_t *blen)
{
	if (*blen < sizeof(TEE_Identity)) {
		*blen = sizeof(TEE_Identity);
		return TEE_ERROR_SHORT_BUFFER;
	}
	*blen = sizeof(TEE_Identity);
	return tee_svc_copy_to_user(buf, &sess->clnt_id, sizeof(TEE_Identity));
}

static TEE_Result get_prop_ta_app_id(struct tee_ta_session *sess,
				     void *buf, size_t *blen)
{
	if (*blen < sizeof(TEE_UUID)) {
		*blen = sizeof(TEE_UUID);
		return TEE_ERROR_SHORT_BUFFER;
	}
	*blen = sizeof(TEE_UUID);
	return tee_svc_copy_to_user(buf, &sess->ctx->uuid, sizeof(TEE_UUID));
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
	struct tee_ta_session *sess;
	TEE_Result res;
	TEE_Result res2;
	const struct tee_props *prop;
	uint32_t klen;
	size_t klen_size;
	uint32_t elen;

	prop = get_prop_struct(prop_set, index);
	if (!prop)
		return TEE_ERROR_ITEM_NOT_FOUND;

	res = tee_ta_get_current_session(&sess);
	if (res != TEE_SUCCESS)
		return res;

	/* Get the property type */
	if (prop_type) {
		res = tee_svc_copy_to_user(prop_type, &prop->prop_type,
					   sizeof(*prop_type));
		if (res != TEE_SUCCESS)
			return res;
	}

	/* Get the property */
	if (buf && blen) {
		res = tee_svc_copy_from_user(&klen, blen, sizeof(klen));
		if (res != TEE_SUCCESS)
			return res;

		if (prop->get_prop_func) {
			klen_size = klen;
			res = prop->get_prop_func(sess, buf, &klen_size);
			klen = klen_size;
			res2 = tee_svc_copy_to_user(blen, &klen, sizeof(*blen));
		} else {
			if (klen < prop->len)
				res = TEE_ERROR_SHORT_BUFFER;
			else
				res = tee_svc_copy_to_user(buf, prop->data,
							   prop->len);
			res2 = tee_svc_copy_to_user(blen, &prop->len,
						    sizeof(*blen));
		}
		if (res2 != TEE_SUCCESS)
			return res2;
		if (res != TEE_SUCCESS)
			return res;
	}

	/* Get the property name */
	if (name && name_len) {
		res = tee_svc_copy_from_user(&klen, name_len, sizeof(klen));
		if (res != TEE_SUCCESS)
			return res;

		elen = strlen(prop->name) + 1;

		if (klen < elen)
			res = TEE_ERROR_SHORT_BUFFER;
		else
			res = tee_svc_copy_to_user(name, prop->name, elen);
		res2 = tee_svc_copy_to_user(name_len, &elen, sizeof(*name_len));
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
	TEE_Result res;
	struct tee_ta_session *sess;
	const struct tee_props *props;
	size_t size;
	const struct tee_props *vendor_props;
	size_t vendor_size;
	char *kname = 0;
	uint32_t i;

	get_prop_set(prop_set, &props, &size, &vendor_props, &vendor_size);
	if (!props)
		return TEE_ERROR_ITEM_NOT_FOUND;

	res = tee_ta_get_current_session(&sess);
	if (res != TEE_SUCCESS)
		goto out;

	if (!name || !name_len) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	kname = malloc(name_len);
	if (!kname)
		return TEE_ERROR_OUT_OF_MEMORY;
	res = tee_svc_copy_from_user(kname, name, name_len);
	if (res != TEE_SUCCESS)
		goto out;
	kname[name_len - 1] = 0;

	res = TEE_ERROR_ITEM_NOT_FOUND;
	for (i = 0; i < size; i++) {
		if (!strcmp(kname, props[i].name)) {
			res = tee_svc_copy_to_user(index, &i, sizeof(*index));
			goto out;
		}
	}
	for (i = size; i < size + vendor_size; i++) {
		if (!strcmp(kname, vendor_props[i - size].name)) {
			res = tee_svc_copy_to_user(index, &i, sizeof(*index));
			goto out;
		}
	}

out:
	free(kname);
	return res;
}

static void utee_param_to_param(struct tee_ta_param *p, struct utee_params *up)
{
	size_t n;
	uint32_t types = up->types;

	p->types = types;
	for (n = 0; n < TEE_NUM_PARAMS; n++) {
		uintptr_t a = up->vals[n * 2];
		size_t b = up->vals[n * 2 + 1];

		switch (TEE_PARAM_TYPE_GET(types, n)) {
		case TEE_PARAM_TYPE_MEMREF_INPUT:
		case TEE_PARAM_TYPE_MEMREF_OUTPUT:
		case TEE_PARAM_TYPE_MEMREF_INOUT:
			p->params[n].memref.buffer = (void *)a;
			p->params[n].memref.size = b;
			p->param_attr[n] = TEE_MATTR_VIRTUAL;
			break;
		case TEE_PARAM_TYPE_VALUE_INPUT:
		case TEE_PARAM_TYPE_VALUE_INOUT:
			p->params[n].value.a = a;
			p->params[n].value.b = b;
			break;
		default:
			p->params[n].value.a = 0;
			p->params[n].value.b = 0;
			break;
		}
	}
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
static TEE_Result tee_svc_copy_param(struct tee_ta_session *sess,
				     struct tee_ta_session *called_sess,
				     struct utee_params *callee_params,
				     struct tee_ta_param *param,
				     void *tmp_buf_va[TEE_NUM_PARAMS],
				     tee_mm_entry_t **mm)
{
	size_t n;
	TEE_Result res;
	size_t req_mem = 0;
	size_t s;
	uint8_t *dst = 0;
	tee_paddr_t dst_pa, src_pa = 0;
	bool ta_private_memref[TEE_NUM_PARAMS];
	struct user_ta_ctx *utc = to_user_ta_ctx(sess->ctx);
	const uint32_t sec_ddr_attr = TEE_MATTR_CACHE_CACHED;

	/* fill 'param' input struct with caller params description buffer */
	if (!callee_params) {
		memset(param, 0, sizeof(*param));
	} else {
		res = tee_mmu_check_access_rights(utc,
			TEE_MEMORY_ACCESS_READ | TEE_MEMORY_ACCESS_ANY_OWNER,
			(tee_uaddr_t)callee_params, sizeof(struct utee_params));
		if (res != TEE_SUCCESS)
			return res;
		utee_param_to_param(param, callee_params);
	}

	if (called_sess && is_static_ta_ctx(called_sess->ctx)) {
		/*
		 * static TA, borrow the mapping of the calling
		 * during this call.
		 */
		return TEE_SUCCESS;
	}

	for (n = 0; n < TEE_NUM_PARAMS; n++) {

		ta_private_memref[n] = false;

		switch (TEE_PARAM_TYPE_GET(param->types, n)) {
		case TEE_PARAM_TYPE_MEMREF_INPUT:
		case TEE_PARAM_TYPE_MEMREF_OUTPUT:
		case TEE_PARAM_TYPE_MEMREF_INOUT:
			if (param->params[n].memref.buffer == NULL) {
				if (param->params[n].memref.size != 0)
					return TEE_ERROR_BAD_PARAMETERS;
				break;
			}
			/* uTA cannot expose its private memory */
			if (tee_mmu_is_vbuf_inside_ta_private(utc,
				    param->params[n].memref.buffer,
				    param->params[n].memref.size)) {

				s = ROUNDUP(param->params[n].memref.size,
						sizeof(uint32_t));
				/* Check overflow */
				if (req_mem + s < req_mem)
					return TEE_ERROR_BAD_PARAMETERS;
				req_mem += s;
				ta_private_memref[n] = true;
				break;
			}
			if (tee_mmu_is_vbuf_intersect_ta_private(utc,
				    param->params[n].memref.buffer,
				    param->params[n].memref.size))
				return TEE_ERROR_BAD_PARAMETERS;

			src_pa = virt_to_phys(param->params[n].memref.buffer);
			if (!src_pa)
				return TEE_ERROR_BAD_PARAMETERS;

			param->param_attr[n] = tee_mmu_user_get_cache_attr(
				utc, (void *)param->params[n].memref.buffer);

			param->params[n].memref.buffer = (void *)src_pa;
			break;

		default:
			break;
		}
	}

	if (req_mem == 0)
		return TEE_SUCCESS;

	/* Allocate section in secure DDR */
	mutex_lock(&tee_ta_mutex);
	*mm = tee_mm_alloc(&tee_mm_sec_ddr, req_mem);
	mutex_unlock(&tee_ta_mutex);
	if (*mm == NULL) {
		DMSG("tee_mm_alloc TEE_ERROR_GENERIC");
		return TEE_ERROR_GENERIC;
	}
	dst_pa = tee_mm_get_smem(*mm);

	/* Get the virtual address for the section in secure DDR */
	dst = phys_to_virt(dst_pa, MEM_AREA_TA_RAM);

	for (n = 0; n < 4; n++) {

		if (ta_private_memref[n] == false)
			continue;

		s = ROUNDUP(param->params[n].memref.size, sizeof(uint32_t));

		switch (TEE_PARAM_TYPE_GET(param->types, n)) {
		case TEE_PARAM_TYPE_MEMREF_INPUT:
		case TEE_PARAM_TYPE_MEMREF_INOUT:
			if (param->params[n].memref.buffer != NULL) {
				res = tee_svc_copy_from_user(dst,
						param->params[n].memref.buffer,
						param->params[n].memref.size);
				if (res != TEE_SUCCESS)
					return res;
				param->param_attr[n] = sec_ddr_attr;
				param->params[n].memref.buffer = (void *)dst_pa;
				tmp_buf_va[n] = dst;
				dst += s;
				dst_pa += s;
			}
			break;

		case TEE_PARAM_TYPE_MEMREF_OUTPUT:
			if (param->params[n].memref.buffer != NULL) {
				param->param_attr[n] = sec_ddr_attr;
				param->params[n].memref.buffer = (void *)dst_pa;
				tmp_buf_va[n] = dst;
				dst += s;
				dst_pa += s;
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
		struct tee_ta_session *sess,
		struct tee_ta_session *called_sess,
		struct tee_ta_param *param,
		void *tmp_buf_va[TEE_NUM_PARAMS],
		struct utee_params *usr_param)
{
	size_t n;
	void *p;
	struct user_ta_ctx *utc = to_user_ta_ctx(sess->ctx);
	bool have_private_mem_map = is_user_ta_ctx(called_sess->ctx);

	for (n = 0; n < TEE_NUM_PARAMS; n++) {
		switch (TEE_PARAM_TYPE_GET(param->types, n)) {
		case TEE_PARAM_TYPE_MEMREF_OUTPUT:
		case TEE_PARAM_TYPE_MEMREF_INOUT:
			p = (void *)(uintptr_t)usr_param->vals[n * 2];

			/* outside TA private => memref is valid, update size */
			if (!tee_mmu_is_vbuf_inside_ta_private(utc, p,
					param->params[n].memref.size)) {
				usr_param->vals[n * 2 + 1] =
					param->params[n].memref.size;
				break;
			}

			/*
			 * If we called a kernel TA the parameters are in shared
			 * memory and no copy is needed.
			 */
			if (have_private_mem_map &&
			    param->params[n].memref.size <=
			    usr_param->vals[n * 2 + 1]) {
				uint8_t *src = tmp_buf_va[n];
				TEE_Result res;

				res = tee_svc_copy_to_user(p, src,
						 param->params[n].memref.size);
				if (res != TEE_SUCCESS)
					return res;

			}
			usr_param->vals[n * 2 + 1] =
				param->params[n].memref.size;
			break;

		case TEE_PARAM_TYPE_VALUE_OUTPUT:
		case TEE_PARAM_TYPE_VALUE_INOUT:
			usr_param->vals[n * 2] = param->params[n].value.a;
			usr_param->vals[n * 2 + 1] = param->params[n].value.b;
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
	TEE_Result res;
	uint32_t ret_o = TEE_ORIGIN_TEE;
	struct tee_ta_session *s = NULL;
	struct tee_ta_session *sess;
	tee_mm_entry_t *mm_param = NULL;
	TEE_UUID *uuid = malloc(sizeof(TEE_UUID));
	struct tee_ta_param *param = malloc(sizeof(struct tee_ta_param));
	TEE_Identity *clnt_id = malloc(sizeof(TEE_Identity));
	void *tmp_buf_va[TEE_NUM_PARAMS];
	struct user_ta_ctx *utc;

	if (uuid == NULL || param == NULL || clnt_id == NULL) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out_free_only;
	}

	memset(param, 0, sizeof(struct tee_ta_param));

	res = tee_ta_get_current_session(&sess);
	if (res != TEE_SUCCESS)
		goto out_free_only;
	utc = to_user_ta_ctx(sess->ctx);

	res = tee_svc_copy_from_user(uuid, dest, sizeof(TEE_UUID));
	if (res != TEE_SUCCESS)
		goto function_exit;

	clnt_id->login = TEE_LOGIN_TRUSTED_APP;
	memcpy(&clnt_id->uuid, &sess->ctx->uuid, sizeof(TEE_UUID));

	res = tee_svc_copy_param(sess, NULL, usr_param, param, tmp_buf_va,
				 &mm_param);
	if (res != TEE_SUCCESS)
		goto function_exit;

	/*
	 * Find session of a multi session TA or a static TA
	 * In such a case, there is no need to ask the supplicant for the TA
	 * code
	 */
	res = tee_ta_open_session(&ret_o, &s, &utc->open_sessions, uuid,
				  clnt_id, cancel_req_to, param);
	if (res != TEE_SUCCESS)
		goto function_exit;

	res = tee_svc_update_out_param(sess, s, param, tmp_buf_va, usr_param);

function_exit:
	if (mm_param) {
		mutex_lock(&tee_ta_mutex);
		tee_mm_free(mm_param);
		mutex_unlock(&tee_ta_mutex);
	}
	if (res == TEE_SUCCESS)
		tee_svc_copy_kaddr_to_uref(ta_sess, s);
	tee_svc_copy_to_user(ret_orig, &ret_o, sizeof(ret_o));

out_free_only:
	free(param);
	free(uuid);
	free(clnt_id);
	return res;
}

TEE_Result syscall_close_ta_session(unsigned long ta_sess)
{
	TEE_Result res;
	struct tee_ta_session *sess;
	TEE_Identity clnt_id;
	struct tee_ta_session *s = tee_svc_uref_to_kaddr(ta_sess);
	struct user_ta_ctx *utc;

	res = tee_ta_get_current_session(&sess);
	if (res != TEE_SUCCESS)
		return res;
	utc = to_user_ta_ctx(sess->ctx);

	clnt_id.login = TEE_LOGIN_TRUSTED_APP;
	memcpy(&clnt_id.uuid, &sess->ctx->uuid, sizeof(TEE_UUID));

	return tee_ta_close_session(s, &utc->open_sessions, &clnt_id);
}

TEE_Result syscall_invoke_ta_command(unsigned long ta_sess,
			unsigned long cancel_req_to, unsigned long cmd_id,
			struct utee_params *usr_param, uint32_t *ret_orig)
{
	TEE_Result res;
	TEE_Result res2;
	uint32_t ret_o = TEE_ORIGIN_TEE;
	struct tee_ta_param param = { 0 };
	TEE_Identity clnt_id;
	struct tee_ta_session *sess;
	struct tee_ta_session *called_sess;
	tee_mm_entry_t *mm_param = NULL;
	void *tmp_buf_va[TEE_NUM_PARAMS];
	struct user_ta_ctx *utc;

	res = tee_ta_get_current_session(&sess);
	if (res != TEE_SUCCESS)
		return res;
	utc = to_user_ta_ctx(sess->ctx);

	called_sess = tee_ta_get_session(
				(vaddr_t)tee_svc_uref_to_kaddr(ta_sess), true,
				&utc->open_sessions);
	if (!called_sess)
		return TEE_ERROR_BAD_PARAMETERS;

	clnt_id.login = TEE_LOGIN_TRUSTED_APP;
	memcpy(&clnt_id.uuid, &sess->ctx->uuid, sizeof(TEE_UUID));

	res = tee_svc_copy_param(sess, called_sess, usr_param, &param,
				 tmp_buf_va, &mm_param);
	if (res != TEE_SUCCESS)
		goto function_exit;

	res = tee_ta_invoke_command(&ret_o, called_sess, &clnt_id,
				    cancel_req_to, cmd_id, &param);

	res2 = tee_svc_update_out_param(sess, called_sess, &param, tmp_buf_va,
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
	if (mm_param) {
		mutex_lock(&tee_ta_mutex);
		tee_mm_free(mm_param);
		mutex_unlock(&tee_ta_mutex);
	}
	if (ret_orig)
		tee_svc_copy_to_user(ret_orig, &ret_o, sizeof(ret_o));
	return res;
}

TEE_Result syscall_check_access_rights(unsigned long flags, const void *buf,
				       size_t len)
{
	TEE_Result res;
	struct tee_ta_session *s;

	res = tee_ta_get_current_session(&s);
	if (res != TEE_SUCCESS)
		return res;

	return tee_mmu_check_access_rights(to_user_ta_ctx(s->ctx), flags,
					   (tee_uaddr_t)buf, len);
}

TEE_Result tee_svc_copy_from_user(void *kaddr, const void *uaddr, size_t len)
{
	TEE_Result res;
	struct tee_ta_session *s;

	res = tee_ta_get_current_session(&s);
	if (res != TEE_SUCCESS)
		return res;

	res = tee_mmu_check_access_rights(to_user_ta_ctx(s->ctx),
					TEE_MEMORY_ACCESS_READ |
					TEE_MEMORY_ACCESS_ANY_OWNER,
					(tee_uaddr_t)uaddr, len);
	if (res != TEE_SUCCESS)
		return res;

	memcpy(kaddr, uaddr, len);
	return TEE_SUCCESS;
}

TEE_Result tee_svc_copy_to_user(void *uaddr, const void *kaddr, size_t len)
{
	TEE_Result res;
	struct tee_ta_session *s;

	res = tee_ta_get_current_session(&s);
	if (res != TEE_SUCCESS)
		return res;

	res = tee_mmu_check_access_rights(to_user_ta_ctx(s->ctx),
					TEE_MEMORY_ACCESS_WRITE |
					TEE_MEMORY_ACCESS_ANY_OWNER,
					(tee_uaddr_t)uaddr, len);
	if (res != TEE_SUCCESS)
		return res;

	memcpy(uaddr, kaddr, len);
	return TEE_SUCCESS;
}

TEE_Result tee_svc_copy_kaddr_to_uref(uint32_t *uref, void *kaddr)
{
	uint32_t ref = tee_svc_kaddr_to_uref(kaddr);

	return tee_svc_copy_to_user(uref, &ref, sizeof(ref));
}

TEE_Result syscall_get_cancellation_flag(uint32_t *cancel)
{
	TEE_Result res;
	struct tee_ta_session *s = NULL;
	uint32_t c;

	res = tee_ta_get_current_session(&s);
	if (res != TEE_SUCCESS)
		return res;

	c = tee_ta_session_is_cancelled(s, NULL);

	return tee_svc_copy_to_user(cancel, &c, sizeof(c));
}

TEE_Result syscall_unmask_cancellation(uint32_t *old_mask)
{
	TEE_Result res;
	struct tee_ta_session *s = NULL;
	uint32_t m;

	res = tee_ta_get_current_session(&s);
	if (res != TEE_SUCCESS)
		return res;

	m = s->cancel_mask;
	s->cancel_mask = false;
	return tee_svc_copy_to_user(old_mask, &m, sizeof(m));
}

TEE_Result syscall_mask_cancellation(uint32_t *old_mask)
{
	TEE_Result res;
	struct tee_ta_session *s = NULL;
	uint32_t m;

	res = tee_ta_get_current_session(&s);
	if (res != TEE_SUCCESS)
		return res;

	m = s->cancel_mask;
	s->cancel_mask = true;
	return tee_svc_copy_to_user(old_mask, &m, sizeof(m));
}

TEE_Result syscall_wait(unsigned long timeout)
{
	TEE_Result res = TEE_SUCCESS;
	uint32_t mytime = 0;
	struct tee_ta_session *s;
	TEE_Time base_time;
	TEE_Time current_time;

	res = tee_ta_get_current_session(&s);
	if (res != TEE_SUCCESS)
		return res;

	res = tee_time_get_sys_time(&base_time);
	if (res != TEE_SUCCESS)
		return res;

	while (true) {
		res = tee_time_get_sys_time(&current_time);
		if (res != TEE_SUCCESS)
			return res;

		if (tee_ta_session_is_cancelled(s, &current_time))
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
	TEE_Result res, res2;
	struct tee_ta_session *s = NULL;
	TEE_Time t;

	res = tee_ta_get_current_session(&s);
	if (res != TEE_SUCCESS)
		return res;

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
		res2 = tee_svc_copy_to_user(mytime, &t, sizeof(t));
		if (res2 != TEE_SUCCESS)
			res = res2;
	}

	return res;
}

TEE_Result syscall_set_ta_time(const TEE_Time *mytime)
{
	TEE_Result res;
	struct tee_ta_session *s = NULL;
	TEE_Time t;

	res = tee_ta_get_current_session(&s);
	if (res != TEE_SUCCESS)
		return res;

	res = tee_svc_copy_from_user(&t, mytime, sizeof(t));
	if (res != TEE_SUCCESS)
		return res;

	return tee_time_set_ta_time((const void *)&s->ctx->uuid, &t);
}
