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
#include <tee/tee_svc.h>
#include <tee/se/svc.h>
#include <trace.h>

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

	return tee_svc_copy_kaddr_to_user32(sess, service_handle, kservice);
}

TEE_Result syscall_se_service_close(uint32_t service_handle)
{
	struct tee_se_service *h = (struct tee_se_service *)service_handle;

	if (!tee_se_service_is_valid(h))
		return TEE_ERROR_BAD_PARAMETERS;

	return tee_se_service_close(h);
}

TEE_Result syscall_se_service_get_readers(uint32_t service_handle,
		uint32_t *reader_handles, size_t *len)
{
	TEE_Result ret;
	size_t i, klen;
	struct tee_se_service *h = (struct tee_se_service *)service_handle;
	struct tee_ta_session *sess;
	struct tee_se_reader_proxy **kreaders;
	size_t kreaders_size;

	if (!tee_se_service_is_valid(h))
		return TEE_ERROR_BAD_PARAMETERS;

	ret = tee_ta_get_current_session(&sess);
	if (ret != TEE_SUCCESS)
		return ret;

	ret = tee_svc_copy_from_user(sess, &klen, len, sizeof(size_t));
	if (ret != TEE_SUCCESS)
		return ret;

	if (klen < tee_se_manager_get_reader_count())
		return TEE_ERROR_SHORT_BUFFER;

	kreaders_size = klen * sizeof(struct tee_se_reader_proxy *);
	kreaders = malloc(kreaders_size);
	if (kreaders == NULL)
		return TEE_ERROR_OUT_OF_MEMORY;

	ret = tee_se_manager_get_readers(kreaders, &klen);
	if (ret != TEE_SUCCESS)
		goto err_free_kreaders;

	for (i = 0; i < klen; i++) {
		ret = tee_svc_copy_kaddr_to_user32(
				sess, &reader_handles[i], kreaders[i]);
		if (ret != TEE_SUCCESS)
			goto err_free_kreaders;
	}

	ret = tee_svc_copy_to_user(sess, len, &klen, sizeof(size_t));

err_free_kreaders:
	free(kreaders);

	return ret;
}

TEE_Result syscall_se_reader_get_prop(uint32_t reader_handle,
		TEE_SEReaderProperties *p)
{
	TEE_Result ret;
	TEE_SEReaderProperties kprop;
	struct tee_se_reader_proxy *r =
		(struct tee_se_reader_proxy *)reader_handle;
	struct tee_ta_session *sess;

	if (!tee_se_manager_is_reader_proxy_valid(r))
		return TEE_ERROR_BAD_PARAMETERS;

	ret = tee_ta_get_current_session(&sess);
	if (ret != TEE_SUCCESS)
		return ret;

	tee_se_reader_get_properties(r, &kprop);

	ret = tee_svc_copy_to_user(sess, p, &kprop, sizeof(kprop));
	if (ret != TEE_SUCCESS)
		return ret;

	return TEE_SUCCESS;
}

TEE_Result syscall_se_reader_get_name(uint32_t reader_handle,
		char *name, size_t *name_len)
{
	TEE_Result ret;
	struct tee_se_reader_proxy *r =
		(struct tee_se_reader_proxy *)reader_handle;
	struct tee_ta_session *sess;
	char *kname;
	size_t kname_len, uname_len;

	if (!tee_se_manager_is_reader_proxy_valid(r))
		return TEE_ERROR_BAD_PARAMETERS;

	ret = tee_ta_get_current_session(&sess);
	if (ret != TEE_SUCCESS)
		return ret;

	ret = tee_svc_copy_from_user(sess, &uname_len,
			name_len, sizeof(size_t));
	if (ret != TEE_SUCCESS)
		return ret;

	kname_len = uname_len;
	tee_se_reader_get_name(r, &kname, &kname_len);

	if (uname_len < kname_len)
		return TEE_ERROR_SHORT_BUFFER;

	ret = tee_svc_copy_to_user(sess, name, kname, kname_len);
	if (ret != TEE_SUCCESS)
		return ret;

	ret = tee_svc_copy_to_user(sess, name_len,
			&kname_len, sizeof(size_t));
	if (ret != TEE_SUCCESS)
		return ret;

	return TEE_SUCCESS;
}

TEE_Result syscall_se_reader_open_session(uint32_t reader_handle,
		uint32_t *session_handle)
{
	TEE_Result ret;
	struct tee_se_reader_proxy *r =
		(struct tee_se_reader_proxy *)reader_handle;
	struct tee_ta_session *sess;
	struct tee_ta_ctx *ctx;
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

	ctx = sess->ctx;
	service = ctx->se_service;
	ret = tee_se_service_add_session(service, ksession);

	ret = tee_svc_copy_kaddr_to_user32(sess, session_handle, ksession);
	if (ret != TEE_SUCCESS)
		return ret;

	return TEE_SUCCESS;
}

TEE_Result syscall_se_reader_close_sessions(uint32_t reader_handle)
{
	TEE_Result ret;
	struct tee_se_reader_proxy *r =
		(struct tee_se_reader_proxy *)reader_handle;
	struct tee_se_service *service;
	struct tee_ta_session *sess;

	if (!tee_se_manager_is_reader_proxy_valid(r))
		return TEE_ERROR_BAD_PARAMETERS;

	ret = tee_ta_get_current_session(&sess);
	if (ret != TEE_SUCCESS)
		return ret;

	service = sess->ctx->se_service;
	tee_se_service_close_sessions_by_reader(service, r);

	return TEE_SUCCESS;
}

TEE_Result syscall_se_session_is_closed(uint32_t session_handle)
{
	TEE_Result ret;
	struct tee_se_session *s =
		(struct tee_se_session *)session_handle;
	struct tee_ta_session *sess;
	struct tee_ta_ctx *ctx;
	struct tee_se_service *service;

	ret = tee_ta_get_current_session(&sess);
	if (ret != TEE_SUCCESS)
		return ret;

	ctx = sess->ctx;
	service = ctx->se_service;

	if (!tee_se_service_is_session_valid(service, s))
		return TEE_ERROR_BAD_PARAMETERS;

	return tee_se_service_is_session_closed(service, s);
}

TEE_Result syscall_se_session_get_atr(uint32_t session_handle,
		void *atr, size_t *atr_len)
{
	TEE_Result ret;
	struct tee_se_session *s =
		(struct tee_se_session *)session_handle;
	struct tee_ta_session *sess;
	struct tee_se_service *service;
	size_t katr_len, uatr_len;
	uint8_t *katr;

	ret = tee_ta_get_current_session(&sess);
	if (ret != TEE_SUCCESS)
		return ret;

	service = sess->ctx->se_service;
	if (!tee_se_service_is_session_valid(service, s))
		return TEE_ERROR_BAD_PARAMETERS;

	ret = tee_svc_copy_from_user(sess,
			&uatr_len, atr_len, sizeof(size_t));
	if (ret != TEE_SUCCESS)
		return ret;

	katr_len = uatr_len;
	ret = tee_se_session_get_atr(s, &katr, &katr_len);
	if (ret != TEE_SUCCESS)
		return ret;

	if (uatr_len < katr_len)
		return TEE_ERROR_SHORT_BUFFER;

	ret = tee_svc_copy_to_user(sess, atr, katr,
			katr_len);
	if (ret != TEE_SUCCESS)
		return ret;

	ret = tee_svc_copy_to_user(sess, atr_len, &katr_len,
			sizeof(size_t));
	if (ret != TEE_SUCCESS)
		return ret;

	return TEE_SUCCESS;
}

TEE_Result syscall_se_session_open_channel(
		uint32_t session_handle, bool is_logical,
		TEE_SEAID *aid, uint32_t *channel_handle)
{
	TEE_Result ret;
	struct tee_se_session *s =
		(struct tee_se_session *)session_handle;
	struct tee_ta_session *sess;
	struct tee_se_service *service;
	TEE_SEAID kaid;
	struct tee_se_aid *se_aid = NULL;
	struct tee_se_channel *kc = NULL;

	ret = tee_ta_get_current_session(&sess);
	if (ret != TEE_SUCCESS)
		return ret;

	service = sess->ctx->se_service;
	if (!tee_se_service_is_session_valid(service, s))
		return TEE_ERROR_BAD_PARAMETERS;

	if (aid) {
		ret = tee_svc_copy_from_user(sess,
				&kaid, aid, sizeof(TEE_SEAID));
		if (ret != TEE_SUCCESS)
			return ret;

		ret = tee_se_aid_create_from_buffer(
				kaid.buffer, kaid.bufferLen,
				&se_aid);
		if (ret != TEE_SUCCESS)
			return ret;
	}

	if (is_logical)
		ret = tee_se_session_open_logical_channel(s, se_aid, &kc);
	else
		ret = tee_se_session_open_basic_channel(s, se_aid, &kc);
	if (ret != TEE_SUCCESS)
		goto error_free_aid;

	ret = tee_svc_copy_kaddr_to_user32(sess, channel_handle, kc);
	if (ret != TEE_SUCCESS)
		goto error_free_aid;

	return TEE_SUCCESS;

error_free_aid:
	if (se_aid)
		tee_se_aid_release(se_aid);
	return TEE_SUCCESS;
}

TEE_Result syscall_se_session_close(uint32_t session_handle)
{
	TEE_Result ret;
	struct tee_se_session *s =
		(struct tee_se_session *)session_handle;
	struct tee_ta_session *sess;
	struct tee_se_service *service;

	ret = tee_ta_get_current_session(&sess);
	if (ret != TEE_SUCCESS)
		return ret;

	service = sess->ctx->se_service;
	if (!tee_se_service_is_session_valid(service, s))
		return TEE_ERROR_BAD_PARAMETERS;

	tee_se_service_close_session(service, s);

	return TEE_SUCCESS;
}

TEE_Result syscall_se_channel_select_next(uint32_t channel_handle)
{
	TEE_Result ret;
	struct tee_se_channel *c =
		(struct tee_se_channel *)channel_handle;
	struct tee_ta_session *sess;
	struct tee_se_service *service;

	ret = tee_ta_get_current_session(&sess);
	if (ret != TEE_SUCCESS)
		return ret;

	service = sess->ctx->se_service;
	if (!tee_se_service_is_channel_valid(service, c))
		return TEE_ERROR_BAD_PARAMETERS;

	tee_se_channel_select_next(c);

	return TEE_SUCCESS;
}

TEE_Result syscall_se_channel_get_select_resp(uint32_t channel_handle,
	void *resp, size_t *resp_len)
{
	TEE_Result ret;
	struct tee_se_channel *c =
		(struct tee_se_channel *)channel_handle;
	struct tee_ta_session *sess;
	struct tee_se_service *service;
	struct resp_apdu *resp_apdu;
	size_t kresp_len, uresp_len;

	ret = tee_ta_get_current_session(&sess);
	if (ret != TEE_SUCCESS)
		return ret;

	service = sess->ctx->se_service;
	if (!tee_se_service_is_channel_valid(service, c))
		return TEE_ERROR_BAD_PARAMETERS;

	ret = tee_svc_copy_from_user(sess, &uresp_len, resp_len,
			sizeof(size_t));
	if (ret != TEE_SUCCESS)
		return TEE_ERROR_BAD_PARAMETERS;

	ret = tee_se_channel_get_select_response(c, &resp_apdu);
	if (ret != TEE_SUCCESS)
		return ret;

	kresp_len = apdu_get_length(to_apdu_base(resp_apdu));
	if (uresp_len < kresp_len)
		return TEE_ERROR_SHORT_BUFFER;

	ret = tee_svc_copy_to_user(sess, resp,
			apdu_get_data(to_apdu_base(resp_apdu)), kresp_len);
	if (ret != TEE_SUCCESS)
		return ret;

	ret = tee_svc_copy_to_user(sess, resp_len,
			&kresp_len, sizeof(size_t));
	if (ret != TEE_SUCCESS)
		return ret;

	return TEE_SUCCESS;
}

TEE_Result syscall_se_channel_transmit(uint32_t channel_handle,
	void *cmd, size_t cmd_len, void *resp, size_t *resp_len)
{
	TEE_Result ret;
	struct tee_se_channel *c =
		(struct tee_se_channel *)channel_handle;
	struct tee_ta_session *sess;
	struct tee_se_service *service;
	struct cmd_apdu *cmd_apdu;
	struct resp_apdu *resp_apdu;
	void *kcmd_buf;
	size_t kresp_len;

	ret = tee_ta_get_current_session(&sess);
	if (ret != TEE_SUCCESS)
		return ret;

	service = sess->ctx->se_service;
	if (!tee_se_service_is_channel_valid(service, c))
		return TEE_ERROR_BAD_PARAMETERS;

	ret = tee_svc_copy_from_user(sess, &kresp_len,
			resp_len, sizeof(size_t));
	if (ret != TEE_SUCCESS)
		return ret;

	kcmd_buf = malloc(cmd_len);
	if (kcmd_buf == NULL)
		return TEE_ERROR_OUT_OF_MEMORY;

	ret = tee_svc_copy_from_user(sess, kcmd_buf, cmd, cmd_len);
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
	ret = tee_svc_copy_to_user(sess, resp_len, &kresp_len,
			sizeof(size_t));
	if (ret != TEE_SUCCESS)
		goto err_free_resp_apdu;

	ret = tee_svc_copy_to_user(sess, resp,
			resp_apdu_get_data(resp_apdu),
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

TEE_Result syscall_se_channel_close(uint32_t channel_handle)
{
	TEE_Result ret;
	struct tee_se_channel *c =
		(struct tee_se_channel *)channel_handle;
	struct tee_ta_session *sess;
	struct tee_se_session *s;
	struct tee_se_service *service;

	ret = tee_ta_get_current_session(&sess);
	if (ret != TEE_SUCCESS)
		return ret;

	service = sess->ctx->se_service;
	if (!tee_se_service_is_channel_valid(service, c))
		return TEE_ERROR_BAD_PARAMETERS;

	s = tee_se_channel_get_session(c);

	tee_se_session_close_channel(s, c);

	return TEE_SUCCESS;
}
