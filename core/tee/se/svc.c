/*
 * Copyright (c) 2014, Linaro Limited
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
#include <kernel/user_ta.h>
#include <tee/tee_svc.h>
#include <tee/se/svc.h>
#include <trace.h>
#include <utee_defines.h>

TEE_Result syscall_se_service_open(uint32_t *service_handle)
{
	struct tee_ta_session *sess;
	struct tee_se_service *kservice;
	TEE_Result ret;

	ret = tee_ta_get_current_session(&sess);
	if (ret != TEE_SUCCESS)
		return ret;

	ret = tee_se_service_open(&kservice);
	if (ret != TEE_SUCCESS)
		return ret;

	return tee_svc_copy_kaddr_to_uref(service_handle, kservice);
}

TEE_Result syscall_se_service_close(unsigned long service_handle)
{
	struct tee_se_service *h = tee_svc_uref_to_kaddr(service_handle);

	if (!tee_se_service_is_valid(h))
		return TEE_ERROR_BAD_PARAMETERS;

	return tee_se_service_close(h);
}

TEE_Result syscall_se_service_get_readers(unsigned long service_handle,
			uint32_t *reader_handles, uint64_t *len)
{
	TEE_Result ret;
	size_t i;
	size_t tmp_klen;
	uint64_t klen;
	struct tee_se_service *h = tee_svc_uref_to_kaddr(service_handle);
	struct tee_ta_session *sess;
	struct tee_se_reader_proxy **kreaders;
	size_t kreaders_size;

	if (!tee_se_service_is_valid(h))
		return TEE_ERROR_BAD_PARAMETERS;

	ret = tee_ta_get_current_session(&sess);
	if (ret != TEE_SUCCESS)
		return ret;

	ret = tee_svc_copy_from_user(&klen, len, sizeof(klen));
	if (ret != TEE_SUCCESS)
		return ret;

	if (klen < tee_se_manager_get_reader_count())
		return TEE_ERROR_SHORT_BUFFER;

	kreaders_size = klen * sizeof(struct tee_se_reader_proxy *);
	kreaders = malloc(kreaders_size);
	if (kreaders == NULL)
		return TEE_ERROR_OUT_OF_MEMORY;

	tmp_klen = klen;
	ret = tee_se_manager_get_readers(kreaders, &tmp_klen);
	if (ret != TEE_SUCCESS)
		goto err_free_kreaders;
	klen = tmp_klen;

	for (i = 0; i < klen; i++) {
		ret = tee_svc_copy_kaddr_to_uref(&reader_handles[i],
						 kreaders[i]);
		if (ret != TEE_SUCCESS)
			goto err_free_kreaders;
	}

	ret = tee_svc_copy_to_user(len, &klen, sizeof(*len));

err_free_kreaders:
	free(kreaders);

	return ret;
}

TEE_Result syscall_se_reader_get_prop(unsigned long reader_handle, uint32_t *p)
{
	TEE_Result ret;
	TEE_SEReaderProperties kprop;
	uint32_t kp = 0;
	struct tee_se_reader_proxy *r = tee_svc_uref_to_kaddr(reader_handle);
	struct tee_ta_session *sess;

	if (!tee_se_manager_is_reader_proxy_valid(r))
		return TEE_ERROR_BAD_PARAMETERS;

	ret = tee_ta_get_current_session(&sess);
	if (ret != TEE_SUCCESS)
		return ret;

	tee_se_reader_get_properties(r, &kprop);
	if (kprop.sePresent)
		kp |= UTEE_SE_READER_PRESENT;
	if (kprop.teeOnly)
		kp |= UTEE_SE_READER_TEE_ONLY;
	if (kprop.selectResponseEnable)
		kp |= UTEE_SE_READER_SELECT_RESPONE_ENABLE;
	ret = tee_svc_copy_to_user(p, &kp, sizeof(kp));
	if (ret != TEE_SUCCESS)
		return ret;

	return TEE_SUCCESS;
}

TEE_Result syscall_se_reader_get_name(unsigned long reader_handle,
			char *name, uint64_t *name_len)
{
	TEE_Result ret;
	struct tee_se_reader_proxy *r = tee_svc_uref_to_kaddr(reader_handle);
	struct tee_ta_session *sess;
	char *kname;
	size_t kname_len;
	uint64_t uname_len;

	if (!tee_se_manager_is_reader_proxy_valid(r))
		return TEE_ERROR_BAD_PARAMETERS;

	ret = tee_ta_get_current_session(&sess);
	if (ret != TEE_SUCCESS)
		return ret;

	ret = tee_svc_copy_from_user(&uname_len, name_len, sizeof(uname_len));
	if (ret != TEE_SUCCESS)
		return ret;

	kname_len = uname_len;
	tee_se_reader_get_name(r, &kname, &kname_len);

	if (uname_len < kname_len)
		return TEE_ERROR_SHORT_BUFFER;

	ret = tee_svc_copy_to_user(name, kname, kname_len);
	if (ret != TEE_SUCCESS)
		return ret;

	uname_len = kname_len;
	ret = tee_svc_copy_to_user(name_len, &uname_len, sizeof(*name_len));
	if (ret != TEE_SUCCESS)
		return ret;

	return TEE_SUCCESS;
}

TEE_Result syscall_se_reader_open_session(unsigned long reader_handle,
			uint32_t *session_handle)
{
	TEE_Result ret;
	struct tee_se_reader_proxy *r = tee_svc_uref_to_kaddr(reader_handle);
	struct tee_ta_session *sess;
	struct tee_se_service *service;
	struct tee_se_session *ksession = NULL;

	if (!tee_se_manager_is_reader_proxy_valid(r))
		return TEE_ERROR_BAD_PARAMETERS;

	ret = tee_ta_get_current_session(&sess);
	if (ret != TEE_SUCCESS)
		return ret;

	ret = tee_se_reader_open_session(r, &ksession);
	if (ret != TEE_SUCCESS)
		return ret;

	service = to_user_ta_ctx(sess->ctx)->se_service;
	ret = tee_se_service_add_session(service, ksession);

	ret = tee_svc_copy_kaddr_to_uref(session_handle, ksession);
	if (ret != TEE_SUCCESS)
		return ret;

	return TEE_SUCCESS;
}

TEE_Result syscall_se_reader_close_sessions(unsigned long reader_handle)
{
	TEE_Result ret;
	struct tee_se_reader_proxy *r = tee_svc_uref_to_kaddr(reader_handle);
	struct tee_se_service *service;
	struct tee_ta_session *sess;

	if (!tee_se_manager_is_reader_proxy_valid(r))
		return TEE_ERROR_BAD_PARAMETERS;

	ret = tee_ta_get_current_session(&sess);
	if (ret != TEE_SUCCESS)
		return ret;

	service = to_user_ta_ctx(sess->ctx)->se_service;
	tee_se_service_close_sessions_by_reader(service, r);

	return TEE_SUCCESS;
}

TEE_Result syscall_se_session_is_closed(unsigned long session_handle)
{
	TEE_Result ret;
	struct tee_se_session *s = tee_svc_uref_to_kaddr(session_handle);
	struct tee_ta_session *sess;
	struct tee_se_service *service;

	ret = tee_ta_get_current_session(&sess);
	if (ret != TEE_SUCCESS)
		return ret;

	service = to_user_ta_ctx(sess->ctx)->se_service;

	if (!tee_se_service_is_session_valid(service, s))
		return TEE_ERROR_BAD_PARAMETERS;

	return tee_se_service_is_session_closed(service, s);
}

TEE_Result syscall_se_session_get_atr(unsigned long session_handle,
			void *atr, uint64_t *atr_len)
{
	TEE_Result ret;
	struct tee_se_session *s = tee_svc_uref_to_kaddr(session_handle);
	struct tee_ta_session *sess;
	struct tee_se_service *service;
	size_t katr_len;
	uint64_t uatr_len;
	uint8_t *katr;

	ret = tee_ta_get_current_session(&sess);
	if (ret != TEE_SUCCESS)
		return ret;

	service = to_user_ta_ctx(sess->ctx)->se_service;
	if (!tee_se_service_is_session_valid(service, s))
		return TEE_ERROR_BAD_PARAMETERS;

	ret = tee_svc_copy_from_user(&uatr_len, atr_len, sizeof(uatr_len));
	if (ret != TEE_SUCCESS)
		return ret;

	katr_len = uatr_len;
	ret = tee_se_session_get_atr(s, &katr, &katr_len);
	if (ret != TEE_SUCCESS)
		return ret;

	if (uatr_len < katr_len)
		return TEE_ERROR_SHORT_BUFFER;

	ret = tee_svc_copy_to_user(atr, katr, katr_len);
	if (ret != TEE_SUCCESS)
		return ret;

	uatr_len = katr_len;
	ret = tee_svc_copy_to_user(atr_len, &uatr_len, sizeof(*atr_len));
	if (ret != TEE_SUCCESS)
		return ret;

	return TEE_SUCCESS;
}

TEE_Result syscall_se_session_open_channel(unsigned long session_handle,
			unsigned long is_logical, const void *aid_buf,
			size_t aid_buf_len, uint32_t *channel_handle)
{
	TEE_Result ret;
	struct tee_se_session *s = tee_svc_uref_to_kaddr(session_handle);
	struct tee_ta_session *sess;
	struct tee_se_service *service;
	struct tee_se_aid *se_aid = NULL;
	struct tee_se_channel *kc = NULL;

	ret = tee_ta_get_current_session(&sess);
	if (ret != TEE_SUCCESS)
		return ret;

	service = to_user_ta_ctx(sess->ctx)->se_service;
	if (!tee_se_service_is_session_valid(service, s))
		return TEE_ERROR_BAD_PARAMETERS;

	if (aid_buf) {
		ret = tee_se_aid_create_from_buffer((void *)aid_buf,
						    aid_buf_len, &se_aid);
		if (ret != TEE_SUCCESS)
			return ret;
	}

	if (is_logical)
		ret = tee_se_session_open_logical_channel(s, se_aid, &kc);
	else
		ret = tee_se_session_open_basic_channel(s, se_aid, &kc);
	if (ret != TEE_SUCCESS)
		goto error_free_aid;

	ret = tee_svc_copy_kaddr_to_uref(channel_handle, kc);
	if (ret != TEE_SUCCESS)
		goto error_free_aid;

	return TEE_SUCCESS;

error_free_aid:
	if (se_aid)
		tee_se_aid_release(se_aid);
	return TEE_SUCCESS;
}

TEE_Result syscall_se_session_close(unsigned long session_handle)
{
	TEE_Result ret;
	struct tee_se_session *s = tee_svc_uref_to_kaddr(session_handle);
	struct tee_ta_session *sess;
	struct tee_se_service *service;

	ret = tee_ta_get_current_session(&sess);
	if (ret != TEE_SUCCESS)
		return ret;

	service = to_user_ta_ctx(sess->ctx)->se_service;
	if (!tee_se_service_is_session_valid(service, s))
		return TEE_ERROR_BAD_PARAMETERS;

	tee_se_service_close_session(service, s);

	return TEE_SUCCESS;
}

TEE_Result syscall_se_channel_select_next(unsigned long channel_handle)
{
	TEE_Result ret;
	struct tee_se_channel *c = tee_svc_uref_to_kaddr(channel_handle);
	struct tee_ta_session *sess;
	struct tee_se_service *service;

	ret = tee_ta_get_current_session(&sess);
	if (ret != TEE_SUCCESS)
		return ret;

	service = to_user_ta_ctx(sess->ctx)->se_service;
	if (!tee_se_service_is_channel_valid(service, c))
		return TEE_ERROR_BAD_PARAMETERS;

	tee_se_channel_select_next(c);

	return TEE_SUCCESS;
}

TEE_Result syscall_se_channel_get_select_resp(unsigned long channel_handle,
			void *resp, uint64_t *resp_len)
{
	TEE_Result ret;
	struct tee_se_channel *c = tee_svc_uref_to_kaddr(channel_handle);
	struct tee_ta_session *sess;
	struct tee_se_service *service;
	struct resp_apdu *resp_apdu;
	size_t kresp_len;
	uint64_t uresp_len;

	ret = tee_ta_get_current_session(&sess);
	if (ret != TEE_SUCCESS)
		return ret;

	service = to_user_ta_ctx(sess->ctx)->se_service;
	if (!tee_se_service_is_channel_valid(service, c))
		return TEE_ERROR_BAD_PARAMETERS;

	ret = tee_svc_copy_from_user(&uresp_len, resp_len, sizeof(size_t));
	if (ret != TEE_SUCCESS)
		return TEE_ERROR_BAD_PARAMETERS;

	ret = tee_se_channel_get_select_response(c, &resp_apdu);
	if (ret != TEE_SUCCESS)
		return ret;

	kresp_len = apdu_get_length(to_apdu_base(resp_apdu));
	if (uresp_len < kresp_len)
		return TEE_ERROR_SHORT_BUFFER;

	ret = tee_svc_copy_to_user(resp,
			apdu_get_data(to_apdu_base(resp_apdu)), kresp_len);
	if (ret != TEE_SUCCESS)
		return ret;

	uresp_len = kresp_len;
	ret = tee_svc_copy_to_user(resp_len, &uresp_len, sizeof(*resp_len));
	if (ret != TEE_SUCCESS)
		return ret;

	return TEE_SUCCESS;
}

TEE_Result syscall_se_channel_transmit(unsigned long channel_handle,
			void *cmd, unsigned long cmd_len, void *resp,
			uint64_t *resp_len)
{
	TEE_Result ret;
	struct tee_se_channel *c = tee_svc_uref_to_kaddr(channel_handle);
	struct tee_ta_session *sess;
	struct tee_se_service *service;
	struct cmd_apdu *cmd_apdu;
	struct resp_apdu *resp_apdu;
	void *kcmd_buf;
	uint64_t kresp_len;

	ret = tee_ta_get_current_session(&sess);
	if (ret != TEE_SUCCESS)
		return ret;

	service = to_user_ta_ctx(sess->ctx)->se_service;
	if (!tee_se_service_is_channel_valid(service, c))
		return TEE_ERROR_BAD_PARAMETERS;

	ret = tee_svc_copy_from_user(&kresp_len, resp_len, sizeof(kresp_len));
	if (ret != TEE_SUCCESS)
		return ret;

	kcmd_buf = malloc(cmd_len);
	if (kcmd_buf == NULL)
		return TEE_ERROR_OUT_OF_MEMORY;

	ret = tee_svc_copy_from_user(kcmd_buf, cmd, cmd_len);
	if (ret != TEE_SUCCESS)
		goto err_free_cmd_buf;

	cmd_apdu =
		alloc_cmd_apdu_from_buf(kcmd_buf, cmd_len);
	if (cmd_apdu == NULL)
		goto err_free_cmd_buf;

	kresp_len -= 2; /* reserve space for SW1 and SW2 */
	resp_apdu = alloc_resp_apdu(kresp_len);
	if (resp_apdu == NULL)
		goto err_free_cmd_apdu;

	ret = tee_se_channel_transmit(c, cmd_apdu, resp_apdu);
	if (ret != TEE_SUCCESS)
		goto err_free_resp_apdu;

	kresp_len = apdu_get_length(to_apdu_base(resp_apdu));
	ret = tee_svc_copy_to_user(resp_len, &kresp_len, sizeof(*resp_len));
	if (ret != TEE_SUCCESS)
		goto err_free_resp_apdu;

	ret = tee_svc_copy_to_user(resp, resp_apdu_get_data(resp_apdu),
				   kresp_len);
	if (ret != TEE_SUCCESS)
		goto err_free_resp_apdu;

	apdu_release(to_apdu_base(resp_apdu));
	apdu_release(to_apdu_base(cmd_apdu));
	free(kcmd_buf);

	return TEE_SUCCESS;

err_free_resp_apdu:
	apdu_release(to_apdu_base(resp_apdu));
err_free_cmd_apdu:
	apdu_release(to_apdu_base(cmd_apdu));
err_free_cmd_buf:
	free(kcmd_buf);
	return ret;
}

TEE_Result syscall_se_channel_close(unsigned long channel_handle)
{
	TEE_Result ret;
	struct tee_se_channel *c = tee_svc_uref_to_kaddr(channel_handle);
	struct tee_ta_session *sess;
	struct tee_se_session *s;
	struct tee_se_service *service;

	ret = tee_ta_get_current_session(&sess);
	if (ret != TEE_SUCCESS)
		return ret;

	service = to_user_ta_ctx(sess->ctx)->se_service;
	if (!tee_se_service_is_channel_valid(service, c))
		return TEE_ERROR_BAD_PARAMETERS;

	s = tee_se_channel_get_session(c);

	tee_se_session_close_channel(s, c);

	return TEE_SUCCESS;
}
