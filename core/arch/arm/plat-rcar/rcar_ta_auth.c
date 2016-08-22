/*
 * Copyright (c) 2015-2016, Renesas Electronics Corporation
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

#include <string.h>
#include <io.h>
#include <trace.h>

#include "rcar_ta_auth.h"
#include "platform_config.h"

#define TA_KEY_CERT_AREA_SIZE		(4096U)
#define TA_CONTENT_CERT_AREA_SIZE	(4096U)
#define TA_NONCACHE_STACK_AREA_SIZE	(4096U)
#define TA_NONCACHE_STACK_ADDR		(TA_VERIFICATION_BASE + \
					TA_VERIFICATION_SIZE)
#define TA_CONTENT_CERT_ADDR		(TA_NONCACHE_STACK_ADDR - \
					TA_NONCACHE_STACK_AREA_SIZE - \
					TA_CONTENT_CERT_AREA_SIZE)
#define TA_KEY_CERT_ADDR		(TA_CONTENT_CERT_ADDR - \
					TA_KEY_CERT_AREA_SIZE)
#define CERT_SIGNATURE_SIZE		(256U)
#define CERT_STORE_ADDR_SIZE		(8U)
#define CERT_REC_LEN_SIZE		(4U)
#define CERT_ADD_DATA_SIZE		(CERT_STORE_ADDR_SIZE + \
					CERT_REC_LEN_SIZE)
#define CERT_OFS_BIT_SIZE		(0xffffU)
#define CERT_BLOCK_SIZE			(4U)
#define CERT_IDX_MAGIC			(0)
#define CERT_IDX_VER			(1)
#define CERT_IDX_SIZE			(2)
#define CERT_IDX_FLAG			(3)
#define KEY_CERT_DEFAULT_SIZE		(0x24cU)
#define CONTENT_CERT_DEFAULT_SIZE	(0x268U)
#define RST_MODEMR			(RST_BASE + 0x0060U)
#define MFIS_SOFTMDR			(MFIS_BASE + 0x0600U)
#define LCS_CM				(0x0U)
#define LCS_DM				(0x1U)
#define LCS_SD				(0x3U)
#define LCS_SE				(0x5U)
#define LCS_FA				(0x7U)
#define SECURE_BOOT_MODE		(0U)
#define NORMAL_BOOT_MODE		(1U)

/* MaskROM API - ROM_SecureBootAPI() */
#ifdef ARM32
#define ADDR_ROM_SECURE_API_FUNC	(0xeb101f54U)
#else
#define ADDR_ROM_SECURE_API_FUNC	(0xeb10dd64U)
#endif

typedef uint32_t (*ROM_FuncReadFlash) (
	uint64_t srcAddr,
	uint8_t *pDest,
	uint32_t sizeToRead
);

#define ROM_SecureBootAPI(A, B, C) ((uint32_t (*)(uint32_t *pKeyCert, \
		uint32_t *pContentCert, ROM_FuncReadFlash pFuncReadFlash)) \
		ADDR_ROM_SECURE_API_FUNC)((A), (B), (C))

/* MaskROM API - ROM_GetLcs() */
typedef uint32_t(*ROM_GETLCS_API)(uint32_t *pLcs);
static const ROM_GETLCS_API ROM_GetLcs = ((ROM_GETLCS_API)0xEB10DFE0U);

/* Declaration of internal function */
static uint32_t get_key_cert_size(const uint32_t *cert_header);
static uint32_t get_content_cert_size(const uint32_t *cert_header);
static uint32_t get_object_size(const void *content_cert);
static uint32_t get_auth_mode(void);
static uint32_t call_maskrom_api(void);

static uint32_t get_key_cert_size(const uint32_t *cert_header)
{
	uint32_t cert_size;

	cert_size = ((cert_header[CERT_IDX_SIZE] & CERT_OFS_BIT_SIZE) *
		CERT_BLOCK_SIZE) + CERT_SIGNATURE_SIZE;

	return cert_size;
}

static uint32_t get_content_cert_size(const uint32_t *cert_header)
{
	uint32_t cert_size;

	cert_size = get_key_cert_size(cert_header) + CERT_ADD_DATA_SIZE;

	return cert_size;
}

static uint32_t get_object_size(const void *content_cert)
{
	uint32_t obj_size;
	const uint32_t *cert_header;
	uint32_t offset;
	const void *obj_len;

	cert_header = (const uint32_t *)content_cert;
	offset = ((cert_header[CERT_IDX_SIZE] & CERT_OFS_BIT_SIZE) *
		CERT_BLOCK_SIZE) + CERT_SIGNATURE_SIZE +
		CERT_STORE_ADDR_SIZE;
	obj_len = (const uint8_t *)content_cert + offset;
	obj_size = *(const uint32_t *)obj_len;
	obj_size *= CERT_BLOCK_SIZE;

	return obj_size;
}

static uint32_t get_auth_mode(void)
{
	uint32_t ret;
	uint32_t lcs;
	uint32_t md;
	uint32_t softmd;
	uint32_t auth_mode;

	/* default is Secure boot */
	auth_mode = SECURE_BOOT_MODE;

	ret = ROM_GetLcs(&lcs);
	if (ret == 0U) {
		if (lcs == LCS_SE) {
			softmd = (read32(MFIS_SOFTMDR) & 0x00000001U);
			if (softmd == 0x1U) {
				/* LCS=Secure + Normal boot (temp setting) */
				auth_mode = NORMAL_BOOT_MODE;
			} else {
				/* LCS=Secure + Secure boot */
			}
		} else {
			md = (read32(RST_MODEMR) & 0x00000020U) >> 5;
			if (md != 0U) {
				/* MD5=1 => LCS=CM/DM + Normal boot */
				auth_mode = NORMAL_BOOT_MODE;
			} else {
				/* MD5=0 => LCS=CM/DM + Secure boot */
			}
		}
	} else {
		EMSG("lcs read error.");
	}

	return auth_mode;
}

/* This function operates in a non-cached stack. */
static uint32_t call_maskrom_api(void)
{
	uint32_t ret;
	uint32_t *key_cert = (uint32_t *)TA_KEY_CERT_ADDR;
	uint32_t *content_cert = (uint32_t *)TA_CONTENT_CERT_ADDR;

	ret = ROM_SecureBootAPI(key_cert, content_cert, NULL);

	return ret;
}

TEE_Result rcar_auth_ta_certificate(const void *key_cert,
				struct shdr **secmem_ta)
{
	TEE_Result res = TEE_ERROR_SECURITY;
	uint32_t ret;
	uint32_t key_cert_size;
	uint32_t content_cert_size;
	uint32_t object_size;
	uint32_t auth_mode;
	const void *content_cert;
	struct shdr *fixed_ta = (struct shdr *)TA_VERIFICATION_BASE;
	uint8_t *fixed_base = (uint8_t *)TA_VERIFICATION_BASE;
	uint8_t *fixed_key_cert = (uint8_t *)TA_KEY_CERT_ADDR;
	uint8_t *fixed_content_cert = (uint8_t *)TA_CONTENT_CERT_ADDR;

	key_cert_size = get_key_cert_size((const uint32_t *)key_cert);
	if (key_cert_size > TA_KEY_CERT_AREA_SIZE) {
		key_cert_size = KEY_CERT_DEFAULT_SIZE;
	}
	content_cert = (const uint8_t *)key_cert + key_cert_size;
	content_cert_size = get_content_cert_size(
				(const uint32_t *)content_cert);
	if (content_cert_size > TA_CONTENT_CERT_AREA_SIZE) {
		content_cert_size = CONTENT_CERT_DEFAULT_SIZE;
	}
	object_size = get_object_size(content_cert);

	DMSG("TA size: key_cert=0x%x content_cert=0x%x shdr+bin=0x%x",
		key_cert_size, content_cert_size, object_size);

	/*
	 *   Fixed memory map          | TotalSize=TA_VERIFICATION_SIZE
	 * ---------------------------------------------------------------
	 * | TA object data area       | TotalSize - [1] - [2] - [3]     |
	 * | (signed header + binary)  |                                 |
	 * ---------------------------------------------------------------
	 * | Key Certificate area      | [1]=TA_KEY_CERT_AREA_SIZE       |
	 * ---------------------------------------------------------------
	 * | Content Certificate area  | [2]=TA_CONTENT_CERT_AREA_SIZE   |
	 * ---------------------------------------------------------------
	 * | Non-cache Stack area      | [3]=TA_NONCACHE_STACK_AREA_SIZE |
	 * ---------------------------------------------------------------
	 */
	if ((fixed_base + object_size) <= fixed_key_cert) {

		/* copy to fixed memory */
		(void)memcpy(fixed_base,
			(const uint8_t *)content_cert + content_cert_size,
			object_size);
		(void)memcpy(fixed_key_cert,
			(const uint8_t *)key_cert,
			key_cert_size);
		(void)memcpy(fixed_content_cert,
			(const uint8_t *)content_cert,
			content_cert_size);

		auth_mode = get_auth_mode();
		if (auth_mode == SECURE_BOOT_MODE) {

			/* call the MaskROM API */
			ret = asm_switch_stack_pointer(
				(uintptr_t)call_maskrom_api,
				TA_NONCACHE_STACK_ADDR);
			if (ret == 0U) {
				DMSG("Secure boot success!");
				*secmem_ta = fixed_ta;
				res = TEE_SUCCESS;
			} else {
				EMSG("Secure boot error. 0x%x", ret);
			}
		} else {
			DMSG("Normal boot");
			*secmem_ta = fixed_ta;
			res = TEE_SUCCESS;
		}
	} else {
		EMSG("Overflow error. r=0x%x", res);
	}

	return res;
}
