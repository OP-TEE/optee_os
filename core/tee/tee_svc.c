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
#include <kernel/util.h>
#include <kernel/tee_common_otp.h>
#include <kernel/tee_common.h>
#include <kernel/tee_compat.h>
#include <tee_api_types.h>
#include <kernel/tee_ta_manager.h>
#include <utee_types.h>
#include <tee/tee_svc.h>
#include <mm/tee_mmu.h>
#include <mm/tee_mm.h>
#include <kernel/tee_rpc.h>
#include <kernel/tee_rpc_types.h>
#include <kernel/tee_time.h>

#include <user_ta_header.h>
#include <kernel/tee_core_trace.h>
#include <kernel/tee_kta_trace.h>
#include <kernel/chip_services.h>
#include <tee/tee_hash.h>


void tee_svc_sys_log(const void *buf, size_t len)
{
	char *kbuf;

	if (len == 0)
		return;

	kbuf = malloc(len);
	if (kbuf == NULL)
		return;
	*kbuf = '\0';

	/* log as Info/Raw traces */
	if (tee_svc_copy_from_user(NULL, kbuf, buf, len) == TEE_SUCCESS)
		ATAMSG_RAW("%s", kbuf);

	free(kbuf);
}

void tee_svc_sys_panic(uint32_t code)
{
	struct tee_ta_session *sess;

	if (tee_ta_get_current_session(&sess) == TEE_SUCCESS) {
		EMSG("Set session 0x%x to panicked", sess);
		sess->ctx->panicked = 1;
		sess->ctx->panic_code = code;

		{
			/*
			 * Force panicking. This memory error will be trapped by
			 * the error exception handler myErrorHandler()
			 */
			EMSG("Following 'DTLB exception in bundle'");
			EMSG("   is generated with code %d", code);
			int *p = 0;
			*p = 1;
		}
	} else {
		DMSG("Panic called from unknown TA");
	}
}

uint32_t tee_svc_sys_dummy(uint32_t *a)
{
	DMSG("tee_svc_sys_dummy: a 0x%x", (unsigned int)a);
	return 0;
}

uint32_t tee_svc_sys_dummy_7args(uint32_t a1, uint32_t a2, uint32_t a3,
				 uint32_t a4, uint32_t a5, uint32_t a6,
				 uint32_t a7)
{
	DMSG("tee_svc_sys_dummy_7args: 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, %x, %x\n",
	     a1, a2, a3, a4, a5, a6, a7);
	return 0;
}

uint32_t tee_svc_sys_nocall(void)
{
	DMSG("No syscall");
	return 0x1;
}

TEE_Result tee_svc_sys_get_property(uint32_t prop, tee_uaddr_t buf, size_t blen)
{
	static const char api_vers[] = "1.0";
	static const char descr[] = "Version N.N";
	/*
	 * Value 100 means:
	 * System time based on REE-controlled timers. Can be tampered by the
	 * REE.  The implementation must still guarantee that the system time
	 * is monotonous, i.e., successive calls to TEE_GetSystemTime must
	 * return increasing values of the system time.
	 */
	static const uint32_t sys_time_prot_lvl = 100;
	static const uint32_t ta_time_prot_lvl = 100;
	struct tee_ta_session *sess;
	TEE_Result res;

	res = tee_ta_get_current_session(&sess);
	if (res != TEE_SUCCESS)
		return res;

	switch (prop) {
	case UTEE_PROP_TEE_API_VERSION:
		if (blen < sizeof(api_vers))
			return TEE_ERROR_SHORT_BUFFER;
		return tee_svc_copy_to_user(sess, (void *)buf, api_vers,
					    sizeof(api_vers));

	case UTEE_PROP_TEE_DESCR:
		if (blen < sizeof(descr))
			return TEE_ERROR_SHORT_BUFFER;
		return tee_svc_copy_to_user(sess, (void *)buf, descr,
					    sizeof(descr));

	case UTEE_PROP_TEE_DEV_ID:
		{
			TEE_UUID uuid;
			const size_t nslen = 4;
			uint8_t data[4 +
				     FVR_DIE_ID_NUM_REGS * sizeof(uint32_t)] = {
			    'S', 'T', 'E', 'E' };

			if (blen < sizeof(uuid))
				return TEE_ERROR_SHORT_BUFFER;

			if (tee_otp_get_die_id
					(data + nslen, sizeof(data) - nslen))
				return TEE_ERROR_BAD_STATE;

			res = tee_hash_createdigest(
					TEE_ALG_SHA256,
					data, sizeof(data),
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

			return tee_svc_copy_to_user(sess, (void *)buf, &uuid,
						    sizeof(TEE_UUID));
		}

	case UTEE_PROP_TEE_SYS_TIME_PROT_LEVEL:
		if (blen < sizeof(sys_time_prot_lvl))
			return TEE_ERROR_SHORT_BUFFER;
		return tee_svc_copy_to_user(sess, (void *)buf,
					    &sys_time_prot_lvl,
					    sizeof(sys_time_prot_lvl));

	case UTEE_PROP_TEE_TA_TIME_PROT_LEVEL:
		if (blen < sizeof(ta_time_prot_lvl))
			return TEE_ERROR_SHORT_BUFFER;
		return tee_svc_copy_to_user(sess, (void *)buf,
					    &ta_time_prot_lvl,
					    sizeof(ta_time_prot_lvl));

	case UTEE_PROP_CLIENT_ID:
		{
			if (blen < sizeof(TEE_Identity))
				return TEE_ERROR_SHORT_BUFFER;

			return tee_svc_copy_to_user(sess, (void *)buf,
						    &sess->clnt_id,
						    sizeof(TEE_Identity));
		}
	case UTEE_PROP_TA_APP_ID:
		{
			if (blen < sizeof(TEE_UUID))
				return TEE_ERROR_SHORT_BUFFER;

			return tee_svc_copy_to_user(sess, (void *)buf,
						    &sess->ctx->head->uuid,
						    sizeof(TEE_UUID));
		}

	default:
		break;
	}
	return TEE_ERROR_NOT_IMPLEMENTED;
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
				     uint32_t param_types,
				     TEE_Param params[TEE_NUM_PARAMS],
				     struct tee_ta_param *param,
				     tee_paddr_t tmp_buf_pa[TEE_NUM_PARAMS],
				     tee_mm_entry_t **mm)
{
	size_t n;
	TEE_Result res;
	size_t req_mem = 0;
	size_t s;
	uint8_t *dst = 0;
	tee_paddr_t dst_pa, src_pa = 0;
	bool ta_private_memref[TEE_NUM_PARAMS];

	param->types = param_types;
	if (params == NULL) {
		if (param->types != 0)
			return TEE_ERROR_BAD_PARAMETERS;
		memset(param->params, 0, sizeof(param->params));
	} else {
		tee_svc_copy_from_user(sess, param->params, params,
				       sizeof(param->params));
	}

	if ((called_sess != NULL) &&
		(called_sess->ctx->static_ta == NULL) &&
		(called_sess->ctx->flags & TA_FLAG_USER_MODE) == 0) {
		/*
		 * kernel TA, borrow the mapping of the calling
		 * during this call.
		 */
		called_sess->calling_sess = sess;
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
			if (tee_mmu_is_vbuf_inside_ta_private(sess->ctx,
				    (uintptr_t)param->params[n].memref.buffer,
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
			if (!tee_mmu_is_vbuf_outside_ta_private(sess->ctx,
				    (uintptr_t)param->params[n].memref.buffer,
				    param->params[n].memref.size))
				return TEE_ERROR_BAD_PARAMETERS;

			if (tee_mmu_user_va2pa(sess->ctx,
					(void *)param->params[n].memref.buffer,
					(void **)&src_pa) != TEE_SUCCESS)
				return TEE_ERROR_BAD_PARAMETERS;

			param->param_attr[n] = tee_mmu_user_get_cache_attr(
				sess->ctx,
				(void *)param->params[n].memref.buffer);

			param->params[n].memref.buffer = (void *)src_pa;
			break;

		default:
			break;
		}
	}

	if (req_mem == 0)
		return TEE_SUCCESS;

	/* Allocate section in secure DDR */
	*mm = tee_mm_alloc(&tee_mm_sec_ddr, req_mem);
	if (*mm == NULL) {
		DMSG("tee_mm_alloc TEE_ERROR_GENERIC");
		return TEE_ERROR_GENERIC;
	}

	/* Get the virtual address for the section in secure DDR */
	res = tee_mmu_kmap(tee_mm_get_smem(*mm), req_mem, &dst);
	if (res != TEE_SUCCESS)
		return res;
	dst_pa = tee_mm_get_smem(*mm);

	for (n = 0; n < 4; n++) {

		if (ta_private_memref[n] == false)
			continue;

		s = ROUNDUP(param->params[n].memref.size, sizeof(uint32_t));

		switch (TEE_PARAM_TYPE_GET(param->types, n)) {
		case TEE_PARAM_TYPE_MEMREF_INPUT:
		case TEE_PARAM_TYPE_MEMREF_INOUT:
			if (param->params[n].memref.buffer != NULL) {
				res = tee_svc_copy_from_user(sess, dst,
							     param->params[n].
							     memref.buffer,
							     param->params[n].
							     memref.size);
				if (res != TEE_SUCCESS)
					return res;

				param->param_attr[n] =
					tee_mmu_kmap_get_cache_attr(dst);
				param->params[n].memref.buffer = (void *)dst_pa;
				tmp_buf_pa[n] = dst_pa;
				dst += s;
				dst_pa += s;
			}
			break;

		case TEE_PARAM_TYPE_MEMREF_OUTPUT:
			if (param->params[n].memref.buffer != NULL) {
				param->param_attr[n] =
					tee_mmu_kmap_get_cache_attr(dst);
				param->params[n].memref.buffer = (void *)dst_pa;
				tmp_buf_pa[n] = dst_pa;
				dst += s;
				dst_pa += s;
			}
			break;

		default:
			continue;
		}
	}

	tee_mmu_kunmap(dst, req_mem);

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
		tee_paddr_t tmp_buf_pa[TEE_NUM_PARAMS],
		TEE_Param params[TEE_NUM_PARAMS])
{
	size_t n;
	bool have_private_mem_map = (called_sess == NULL) ||
		(called_sess->ctx->static_ta != NULL) ||
		((called_sess->ctx->flags & TA_FLAG_USER_MODE) != 0);

	tee_ta_set_current_session(sess);

	for (n = 0; n < TEE_NUM_PARAMS; n++) {
		switch (TEE_PARAM_TYPE_GET(param->types, n)) {
		case TEE_PARAM_TYPE_MEMREF_OUTPUT:
		case TEE_PARAM_TYPE_MEMREF_INOUT:

			/* outside TA private => memref is valid, update size */
			if (!tee_mmu_is_vbuf_inside_ta_private(sess->ctx,
					(uintptr_t)params[n].memref.buffer,
					param->params[n].memref.size)) {
				params[n].memref.size =
					param->params[n].memref.size;
				break;
			}

			/*
			 * If we called a kernel TA the parameters are in shared
			 * memory and no copy is needed.
			 */
			if (have_private_mem_map &&
			    param->params[n].memref.size <=
			    params[n].memref.size) {
				uint8_t *src = 0;
				TEE_Result res;

				/* FIXME: TA_RAM is already mapped ! */
				res = tee_mmu_kmap(tmp_buf_pa[n],
					param->params[n].memref.size, &src);
				if (res != TEE_SUCCESS)
					return TEE_ERROR_GENERIC;

				res = tee_svc_copy_to_user(sess,
							 params[n].memref.
							 buffer, src,
							 param->params[n].
							 memref.size);
				if (res != TEE_SUCCESS)
					return res;
				tee_mmu_kunmap(src,
					       param->params[n].memref.size);

			}
			params[n].memref.size = param->params[n].memref.size;
			break;

		case TEE_PARAM_TYPE_VALUE_OUTPUT:
		case TEE_PARAM_TYPE_VALUE_INOUT:
			params[n].value = param->params[n].value;
			break;

		default:
			continue;
		}
	}

	return TEE_SUCCESS;
}

/* Called when a TA calls an OpenSession on another TA */
TEE_Result tee_svc_open_ta_session(const TEE_UUID *dest,
				   uint32_t cancel_req_to, uint32_t param_types,
				   TEE_Param params[4],
				   TEE_TASessionHandle *ta_sess,
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
	tee_paddr_t tmp_buf_pa[TEE_NUM_PARAMS];

	if (uuid == NULL || param == NULL || clnt_id == NULL) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out_free_only;
	}

	memset(param, 0, sizeof(struct tee_ta_param));

	res = tee_ta_get_current_session(&sess);
	if (res != TEE_SUCCESS)
		goto out_free_only;

	res = tee_svc_copy_from_user(sess, uuid, dest, sizeof(TEE_UUID));
	if (res != TEE_SUCCESS)
		goto function_exit;

	clnt_id->login = TEE_LOGIN_TRUSTED_APP;
	memcpy(&clnt_id->uuid, &sess->ctx->head->uuid, sizeof(TEE_UUID));

	res = tee_svc_copy_param(sess, NULL, param_types, params, param,
				 tmp_buf_pa, &mm_param);
	if (res != TEE_SUCCESS)
		goto function_exit;

	/*
	 * Find session of a multi session TA or a static TA
	 * In such a case, there is no need to ask the supplicant for the TA
	 * code
	 */
	res = tee_ta_open_session(&ret_o, &s, &sess->ctx->open_sessions, uuid,
				  clnt_id, cancel_req_to, param);
	if (res != TEE_SUCCESS)
		goto function_exit;

	res = tee_svc_update_out_param(sess, NULL, param, tmp_buf_pa, params);
	if (res != TEE_SUCCESS)
		goto function_exit;

function_exit:
	tee_ta_set_current_session(sess);

	if (mm_param != NULL) {
		TEE_Result res2;
		void *va = 0;

		res2 =
		    tee_mmu_kmap_pa2va((void *)tee_mm_get_smem(mm_param), &va);
		if (res2 == TEE_SUCCESS)
			tee_mmu_kunmap(va, tee_mm_get_bytes(mm_param));
	}
	tee_mm_free(mm_param);
	tee_svc_copy_to_user(sess, ta_sess, &s, sizeof(s));
	tee_svc_copy_to_user(sess, ret_orig, &ret_o, sizeof(ret_o));

out_free_only:
	free(param);
	free(uuid);
	free(clnt_id);
	return res;
}

TEE_Result tee_svc_close_ta_session(TEE_TASessionHandle ta_sess)
{
	TEE_Result res;
	struct tee_ta_session *sess;

	res = tee_ta_get_current_session(&sess);
	if (res != TEE_SUCCESS)
		return res;

	tee_ta_set_current_session(NULL);

	res =
	    tee_ta_close_session((uint32_t)ta_sess, &sess->ctx->open_sessions);
	tee_ta_set_current_session(sess);
	return res;
}

TEE_Result tee_svc_invoke_ta_command(TEE_TASessionHandle ta_sess,
				     uint32_t cancel_req_to, uint32_t cmd_id,
				     uint32_t param_types, TEE_Param params[4],
				     uint32_t *ret_orig)
{
	TEE_Result res;
	uint32_t ret_o = TEE_ORIGIN_TEE;
	struct tee_ta_param param = { 0 };
	TEE_Identity clnt_id;
	struct tee_ta_session *sess;
	struct tee_ta_session *called_sess = (struct tee_ta_session *)ta_sess;
	tee_mm_entry_t *mm_param = NULL;
	tee_paddr_t tmp_buf_pa[TEE_NUM_PARAMS];

	res = tee_ta_get_current_session(&sess);
	if (res != TEE_SUCCESS)
		return res;

	res =
	    tee_ta_verify_session_pointer(called_sess,
					  &sess->ctx->open_sessions);
	if (res != TEE_SUCCESS)
		return res;

	res = tee_svc_copy_param(sess, called_sess, param_types, params,
				 &param, tmp_buf_pa, &mm_param);
	if (res != TEE_SUCCESS)
		goto function_exit;

	res =
	    tee_ta_invoke_command(&ret_o, called_sess, &clnt_id, cancel_req_to,
				  cmd_id, &param);
	if (res != TEE_SUCCESS)
		goto function_exit;

	res = tee_svc_update_out_param(sess, called_sess, &param, tmp_buf_pa,
				       params);
	if (res != TEE_SUCCESS)
		goto function_exit;

function_exit:
	tee_ta_set_current_session(sess);
	called_sess->calling_sess = NULL; /* clear eventual borrowed mapping */

	if (mm_param != NULL) {
		TEE_Result res2;
		void *va = 0;

		res2 =
		    tee_mmu_kmap_pa2va((void *)tee_mm_get_smem(mm_param), &va);
		if (res2 == TEE_SUCCESS)
			tee_mmu_kunmap(va, tee_mm_get_bytes(mm_param));
	}
	tee_mm_free(mm_param);
	if (ret_orig)
		tee_svc_copy_to_user(sess, ret_orig, &ret_o, sizeof(ret_o));
	return res;
}

TEE_Result tee_svc_check_access_rights(uint32_t flags, const void *buf,
				       size_t len)
{
	TEE_Result res;
	struct tee_ta_session *s;

	res = tee_ta_get_current_session(&s);
	if (res != TEE_SUCCESS)
		return res;

	return tee_mmu_check_access_rights(s->ctx, flags, (tee_uaddr_t)buf,
					   len);
}

TEE_Result tee_svc_copy_from_user(struct tee_ta_session *sess, void *kaddr,
				  const void *uaddr, size_t len)
{
	TEE_Result res;
	struct tee_ta_session *s;

	if (sess == NULL) {
		res = tee_ta_get_current_session(&s);
		if (res != TEE_SUCCESS)
			return res;
	} else {
		s = sess;
		tee_ta_set_current_session(s);
	}
	res =
	    tee_mmu_check_access_rights(s->ctx,
					TEE_MEMORY_ACCESS_READ |
					TEE_MEMORY_ACCESS_ANY_OWNER,
					(tee_uaddr_t)uaddr, len);
	if (res != TEE_SUCCESS)
		return res;

	memcpy(kaddr, uaddr, len);
	return TEE_SUCCESS;
}

TEE_Result tee_svc_copy_to_user(struct tee_ta_session *sess, void *uaddr,
				const void *kaddr, size_t len)
{
	TEE_Result res;
	struct tee_ta_session *s;

	if (sess == NULL) {
		res = tee_ta_get_current_session(&s);
		if (res != TEE_SUCCESS)
			return res;
	} else {
		s = sess;
		tee_ta_set_current_session(s);
	}

	res =
	    tee_mmu_check_access_rights(s->ctx,
					TEE_MEMORY_ACCESS_WRITE |
					TEE_MEMORY_ACCESS_ANY_OWNER,
					(tee_uaddr_t)uaddr, len);
	if (res != TEE_SUCCESS)
		return res;

	memcpy(uaddr, kaddr, len);
	return TEE_SUCCESS;
}

static bool session_is_cancelled(struct tee_ta_session *s, TEE_Time *curr_time)
{
	TEE_Time current_time;

	if (s->cancel_mask)
		return false;

	if (s->cancel)
		return true;

	if (s->cancel_time.seconds == UINT32_MAX)
		return false;

	if (curr_time != NULL)
		current_time = *curr_time;
	else if (tee_time_get_sys_time(&current_time) != TEE_SUCCESS)
		return false;

	if (current_time.seconds > s->cancel_time.seconds ||
	    (current_time.seconds == s->cancel_time.seconds &&
	     current_time.millis >= s->cancel_time.millis)) {
		return true;
	}

	return false;
}

TEE_Result tee_svc_get_cancellation_flag(bool *cancel)
{
	TEE_Result res;
	struct tee_ta_session *s = NULL;
	bool c;

	res = tee_ta_get_current_session(&s);
	if (res != TEE_SUCCESS)
		return res;

	c = session_is_cancelled(s, NULL);

	return tee_svc_copy_to_user(s, cancel, &c, sizeof(c));
}

TEE_Result tee_svc_unmask_cancellation(bool *old_mask)
{
	TEE_Result res;
	struct tee_ta_session *s = NULL;
	bool m;

	res = tee_ta_get_current_session(&s);
	if (res != TEE_SUCCESS)
		return res;

	m = s->cancel_mask;
	s->cancel_mask = false;
	return tee_svc_copy_to_user(s, old_mask, &m, sizeof(m));
}

TEE_Result tee_svc_mask_cancellation(bool *old_mask)
{
	TEE_Result res;
	struct tee_ta_session *s = NULL;
	bool m;

	res = tee_ta_get_current_session(&s);
	if (res != TEE_SUCCESS)
		return res;

	m = s->cancel_mask;
	s->cancel_mask = true;
	return tee_svc_copy_to_user(s, old_mask, &m, sizeof(m));
}

TEE_Result tee_svc_wait(uint32_t timeout)
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

		if (session_is_cancelled(s, &current_time))
			return TEE_ERROR_CANCEL;

		mytime = (current_time.seconds - base_time.seconds) * 1000 +
		    (int)current_time.millis - (int)base_time.millis;
		if (mytime >= timeout)
			return TEE_SUCCESS;

		tee_time_wait(timeout - mytime);
	}

	return res;
}

TEE_Result tee_svc_get_time(enum utee_time_category cat, TEE_Time *mytime)
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
		res =
		    tee_time_get_ta_time((const void *)&s->ctx->head->uuid, &t);
		break;
	case UTEE_TIME_CAT_REE:
		res = tee_time_get_ree_time(&t);
		break;
	default:
		res = TEE_ERROR_BAD_PARAMETERS;
		break;
	}

	if (res == TEE_SUCCESS || res == TEE_ERROR_OVERFLOW) {
		res2 = tee_svc_copy_to_user(s, mytime, &t, sizeof(t));
		if (res2 != TEE_SUCCESS)
			res = res2;
	}

	return res;
}

TEE_Result tee_svc_set_ta_time(const TEE_Time *mytime)
{
	TEE_Result res;
	struct tee_ta_session *s = NULL;
	TEE_Time t;

	res = tee_ta_get_current_session(&s);
	if (res != TEE_SUCCESS)
		return res;

	res = tee_svc_copy_from_user(s, &t, mytime, sizeof(t));
	if (res != TEE_SUCCESS)
		return res;

	return tee_time_set_ta_time((const void *)&s->ctx->head->uuid, &t);
}
