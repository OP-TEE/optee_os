/*
 * Copyright (c) 2015, Linaro Limited
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

#include <stdio.h>
#include <stdlib.h>
#include <kernel/static_ta.h>
#include <trace.h>
#include <kernel/tee_common_unpg.h>
#include <tee/tee_fs_key_manager.h>


#define TA_NAME		"tee_fs_key_manager_tests.ta"

#define CMD_SELF_TESTS	0

#define ENC_FS_KEY_MANAGER_TEST_UUID \
		{ 0x17E5E280, 0xD12E, 0x11E4,  \
		{ 0xA4, 0x1A, 0x00, 0x02, 0xA5, 0xD5, 0xC5, 0x1B } }

#define DUMP_BUF_MAX	256

static uint8_t test_data[] = {
	0x00, 0x6E, 0x04, 0x57, 0x08, 0xFB, 0x71, 0x96,
	0x00, 0x2E, 0x55, 0x3D, 0x02, 0xC3, 0xA6, 0x92,
	0x00, 0xC3, 0xEF, 0x8A, 0xB2, 0x34, 0x53, 0xE6,
	0x00, 0x74, 0x9C, 0xD6, 0x36, 0xE7, 0xA8, 0x00
};

static char *print_buf(char *buf, size_t *remain_size, const char *fmt, ...)
	__attribute__((__format__(__printf__, 3, 4)));

static char *print_buf(char *buf, size_t *remain_size, const char *fmt, ...)
{
	va_list ap;
	size_t len;

	va_start(ap, fmt);
	len = vsnprintf(buf, *remain_size, fmt, ap);
	buf += len;
	*remain_size -= len;
	va_end(ap);
	return buf;
}

static void dump_hex(char *buf, size_t *remain_size, uint8_t *input_buf,
		size_t input_size)
{
	size_t i;

	for (i = 0; i < input_size; i++)
		buf = print_buf(buf, remain_size, "%02X ", input_buf[i]);
}

static void print_hex(uint8_t *input_buf, size_t input_size)
{
	char buf[DUMP_BUF_MAX];
	size_t remain = sizeof(buf);

	dump_hex(buf, &remain, input_buf, input_size);
	DMSG("%s", buf);
}

/*
 * Trusted Application Entry Points
 */

static TEE_Result create_ta(void)
{
	DMSG("create entry point for static ta \"%s\"", TA_NAME);
	return TEE_SUCCESS;
}

static void destroy_ta(void)
{
	DMSG("destroy entry point for static ta \"%s\"", TA_NAME);
}

static TEE_Result open_session(uint32_t nParamTypes __unused,
		TEE_Param pParams[4] __unused, void **ppSessionContext __unused)
{
	DMSG("open entry point for static ta \"%s\"", TA_NAME);
	return TEE_SUCCESS;
}

static void close_session(void *pSessionContext __unused)
{
	DMSG("close entry point for static ta \"%s\"", TA_NAME);
}


static TEE_Result test_file_decrypt_with_invalid_content(void)
{
	TEE_Result res = TEE_SUCCESS;
	size_t header_size;
	size_t encrypt_data_out_size;
	uint8_t *encrypt_data_out = NULL;
	size_t decrypt_data_out_size;
	uint8_t *decrypt_data_out = NULL;
	uint8_t tmp_byte;
	uint8_t encrypted_fek[TEE_FS_KM_FEK_SIZE];

	DMSG("Start");

	/* data encryption */
	header_size = tee_fs_get_header_size(META_FILE);

	encrypt_data_out_size = header_size + sizeof(test_data);
	encrypt_data_out = malloc(encrypt_data_out_size);
	if (!encrypt_data_out) {
		EMSG("malloc for encrypt data buffer failed");
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto exit;
	}

	res = tee_fs_encrypt_file(META_FILE,
			test_data, sizeof(test_data),
			encrypt_data_out, &encrypt_data_out_size,
			encrypted_fek);
	if (res != TEE_SUCCESS) {
		EMSG("file encryption failed");
		goto exit;
	}

	/* data decryption */
	decrypt_data_out_size = sizeof(test_data);
	decrypt_data_out = malloc(decrypt_data_out_size);
	if (!decrypt_data_out) {
		EMSG("malloc for decrypt data buffer failed");
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto exit;
	}

	/* case1: data decryption with modified encrypted_key */
	tmp_byte = *(encrypt_data_out + 4);
	*(encrypt_data_out + 4) = ~tmp_byte;

	DMSG("case1: decryption with modified encrypted FEK");

	res = tee_fs_decrypt_file(META_FILE,
			encrypt_data_out, encrypt_data_out_size,
			decrypt_data_out, &decrypt_data_out_size,
			encrypted_fek);
	if (res == TEE_ERROR_MAC_INVALID) {
		DMSG("case1: passed, return code=%x", res);
	} else {
		EMSG("case1: failed, return code=%x", res);
		res = TEE_ERROR_GENERIC;
		goto exit;
	}

	*(encrypt_data_out + 4) = tmp_byte;

	/* case2: data decryption with modified iv */
	tmp_byte = *(encrypt_data_out + 20);
	*(encrypt_data_out + 20) = ~tmp_byte;

	DMSG("case2: decryption with modified IV");

	res = tee_fs_decrypt_file(META_FILE,
			encrypt_data_out, encrypt_data_out_size,
			decrypt_data_out, &decrypt_data_out_size,
			encrypted_fek);
	if (res == TEE_ERROR_MAC_INVALID) {
		DMSG("case2: passed, return code=%x", res);
	} else {
		EMSG("case2: failed, return code=%x", res);
		res = TEE_ERROR_GENERIC;
		goto exit;
	}

	*(encrypt_data_out + 20) = tmp_byte;

	/* case3: data decryption with modified cipher text */
	tmp_byte = *(encrypt_data_out + encrypt_data_out_size - 5);
	*(encrypt_data_out + encrypt_data_out_size - 5) = ~tmp_byte;

	DMSG("case3: decryption with modified cipher text");

	res = tee_fs_decrypt_file(META_FILE,
			encrypt_data_out, encrypt_data_out_size,
			decrypt_data_out, &decrypt_data_out_size,
			encrypted_fek);
	if (res == TEE_ERROR_MAC_INVALID) {
		DMSG("case3: passed, return code=%x", res);
	} else {
		EMSG("case3: failed, return code=%x", res);
		res = TEE_ERROR_GENERIC;
		goto exit;
	}

	*(encrypt_data_out + encrypt_data_out_size - 5) = tmp_byte;

	/* case4: data decryption with shorter cipher text length */
	DMSG("case4: decryption with shorter cipher text length");

	res = tee_fs_decrypt_file(META_FILE,
			encrypt_data_out, encrypt_data_out_size - 1,
			decrypt_data_out, &decrypt_data_out_size,
			encrypted_fek);
	if (res == TEE_ERROR_MAC_INVALID) {
		DMSG("case4: passed, return code=%x", res);
	} else {
		EMSG("case4: failed, return code=%x", res);
		res = TEE_ERROR_GENERIC;
		goto exit;
	}

	/* case5: data decryption with shorter plain text buffer */
	decrypt_data_out_size = sizeof(test_data) - 1;

	DMSG("case5: decryption with shorter plain text buffer");

	res = tee_fs_decrypt_file(META_FILE,
			encrypt_data_out, encrypt_data_out_size,
			decrypt_data_out, &decrypt_data_out_size,
			encrypted_fek);
	if (res == TEE_ERROR_SHORT_BUFFER) {
		DMSG("case5: passed, return code=%x", res);
	} else {
		EMSG("case5: failed, return code=%x", res);
		res = TEE_ERROR_GENERIC;
		goto exit;
	}

	decrypt_data_out_size = encrypt_data_out_size;

	/* data decryption with correct encrypted data */
	DMSG("good path test - decryption with correct data");

	res = tee_fs_decrypt_file(META_FILE,
			encrypt_data_out, encrypt_data_out_size,
			decrypt_data_out, &decrypt_data_out_size,
			encrypted_fek);
	if (res != TEE_SUCCESS) {
		EMSG("failed to decrypted data, return code=%x", res);
		goto exit;
	}

	/* data comparison */
	if (memcmp(test_data, decrypt_data_out, sizeof(test_data)) != 0) {
		EMSG("decrypted data doest not correct");
		res = TEE_ERROR_GENERIC;
	} else {
		DMSG("good path test - passed");
	}

exit:
	if (encrypt_data_out != NULL)
		free(encrypt_data_out);

	if (decrypt_data_out != NULL)
		free(decrypt_data_out);

	DMSG("Finish");

	return res;
}

static TEE_Result test_file_decrypt_success(void)
{
	TEE_Result res = TEE_SUCCESS;
	size_t header_size;
	size_t encrypt_data_out_size;
	uint8_t *encrypt_data_out = NULL;
	size_t decrypt_data_out_size;
	uint8_t *decrypt_data_out = NULL;
	uint8_t encrypted_fek[TEE_FS_KM_FEK_SIZE];

	DMSG("Start");

	res = tee_fs_generate_fek(encrypted_fek, TEE_FS_KM_FEK_SIZE);
	if (res != TEE_SUCCESS)
		goto exit;

	/* data encryption */
	header_size = tee_fs_get_header_size(META_FILE);

	encrypt_data_out_size = header_size + sizeof(test_data);
	encrypt_data_out = malloc(encrypt_data_out_size);
	if (!encrypt_data_out) {
		EMSG("malloc for encrypt data buffer failed");
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto exit;
	}

	res = tee_fs_encrypt_file(META_FILE,
			test_data, sizeof(test_data),
			encrypt_data_out, &encrypt_data_out_size,
			encrypted_fek);
	if (res != TEE_SUCCESS) {
		EMSG("file encryption failed");
		goto exit;
	}


	/* data decryption */
	decrypt_data_out_size = sizeof(test_data);
	decrypt_data_out = malloc(decrypt_data_out_size);
	if (!decrypt_data_out) {
		EMSG("malloc for decrypt data buffer failed");
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto exit;
	}

	res = tee_fs_decrypt_file(META_FILE,
			encrypt_data_out, encrypt_data_out_size,
			decrypt_data_out, &decrypt_data_out_size,
			encrypted_fek);
	if (res != TEE_SUCCESS)
		goto exit;

	/* data comparison */
	if (memcmp(test_data, decrypt_data_out, sizeof(test_data)) != 0) {
		EMSG("Data compare failed");
		res = TEE_ERROR_GENERIC;
	}

exit:
	/* dump data for debug */
	if (res != TEE_SUCCESS)
		DMSG("return code = %x", res);
	else {
		DMSG("Test Data (%zu bytes)", sizeof(test_data));
		print_hex(test_data, sizeof(test_data));
		DMSG("Encrypted Data (%zu bytes)", encrypt_data_out_size);
		print_hex(encrypt_data_out, encrypt_data_out_size);
		DMSG("Decrypted Data (%zu bytes)", decrypt_data_out_size);
		print_hex(decrypt_data_out, decrypt_data_out_size);
	}

	if (encrypt_data_out != NULL)
		free(encrypt_data_out);

	if (decrypt_data_out != NULL)
		free(decrypt_data_out);

	DMSG("Finish");

	return res;
}

static TEE_Result self_tests(
			uint32_t nParamTypes __unused,
			TEE_Param pParams[TEE_NUM_PARAMS] __unused)
{
	TEE_Result res;

	res = test_file_decrypt_success();
	if (res != TEE_SUCCESS)
		return res;

	res = test_file_decrypt_with_invalid_content();
	if (res != TEE_SUCCESS)
		return res;

	return TEE_SUCCESS;
}

static TEE_Result invoke_command(void *pSessionContext __unused,
		uint32_t nCommandID, uint32_t nParamTypes, TEE_Param pParams[4])
{
	DMSG("command entry point for static ta \"%s\"", TA_NAME);

	switch (nCommandID) {
	case CMD_SELF_TESTS:
		return self_tests(nParamTypes, pParams);
	default:
		break;
	}
	return TEE_ERROR_BAD_PARAMETERS;
}

static_ta_register(.uuid = ENC_FS_KEY_MANAGER_TEST_UUID, .name = TA_NAME,
		   .create_entry_point = create_ta,
		   .destroy_entry_point = destroy_ta,
		   .open_session_entry_point = open_session,
		   .close_session_entry_point = close_session,
		   .invoke_command_entry_point = invoke_command);
