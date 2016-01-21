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
#include <types_ext.h>
#include <stdlib.h>
#include <string.h>
#include <string_ext.h>
#include <util.h>
#include <trace.h>
#include <tee_api_types.h>
#include <kernel/mutex.h>
#include <kernel/tee_common_otp.h>
#include <kernel/tee_rpc.h>
#include <kernel/thread.h>
#include <kernel/tee_ta_manager.h>
#include <tee/tee_rpmb.h>
#include <kernel/chip_services.h>
#include <kernel/tee_misc.h>
#include <tee/tee_cryp_provider.h>
#include <tee/tee_cryp_utl.h>
#include <tee/tee_fs_key_manager.h>
#include <sm/teesmc.h>
#include <mm/core_mmu.h>

#define RPMB_DATA_OFFSET            (RPMB_STUFF_DATA_SIZE + RPMB_KEY_MAC_SIZE)
#define RPMB_MAC_PROTECT_DATA_SIZE  (RPMB_DATA_FRAME_SIZE - RPMB_DATA_OFFSET)

#define RPMB_MSG_TYPE_REQ_AUTH_KEY_PROGRAM          0x0001
#define RPMB_MSG_TYPE_REQ_WRITE_COUNTER_VAL_READ    0x0002
#define RPMB_MSG_TYPE_REQ_AUTH_DATA_WRITE           0x0003
#define RPMB_MSG_TYPE_REQ_AUTH_DATA_READ            0x0004
#define RPMB_MSG_TYPE_REQ_RESULT_READ               0x0005
#define RPMB_MSG_TYPE_RESP_AUTH_KEY_PROGRAM         0x0100
#define RPMB_MSG_TYPE_RESP_WRITE_COUNTER_VAL_READ   0x0200
#define RPMB_MSG_TYPE_RESP_AUTH_DATA_WRITE          0x0300
#define RPMB_MSG_TYPE_RESP_AUTH_DATA_READ           0x0400

#define RPMB_STUFF_DATA_SIZE                        196
#define RPMB_KEY_MAC_SIZE                           32
#define RPMB_DATA_SIZE                              256
#define RPMB_NONCE_SIZE                             16
#define RPMB_DATA_FRAME_SIZE                        512

#define RPMB_RESULT_OK                              0x00
#define RPMB_RESULT_GENERAL_FAILURE                 0x01
#define RPMB_RESULT_AUTH_FAILURE                    0x02
#define RPMB_RESULT_COUNTER_FAILURE                 0x03
#define RPMB_RESULT_ADDRESS_FAILURE                 0x04
#define RPMB_RESULT_WRITE_FAILURE                   0x05
#define RPMB_RESULT_READ_FAILURE                    0x06
#define RPMB_RESULT_AUTH_KEY_NOT_PROGRAMMED         0x07
#define RPMB_RESULT_MASK                            0x3F
#define RPMB_RESULT_WR_CNT_EXPIRED                  0x80

/* RPMB internal commands */
#define RPMB_CMD_DATA_REQ      0x00
#define RPMB_CMD_GET_DEV_INFO  0x01

#define RPMB_SIZE_SINGLE (128 * 1024)

/* Error codes for get_dev_info request/response. */
#define RPMB_CMD_GET_DEV_INFO_RET_OK     0x00
#define RPMB_CMD_GET_DEV_INFO_RET_ERROR  0x01

struct rpmb_data_frame {
	uint8_t stuff_bytes[RPMB_STUFF_DATA_SIZE];
	uint8_t key_mac[RPMB_KEY_MAC_SIZE];
	uint8_t data[RPMB_DATA_SIZE];
	uint8_t nonce[RPMB_NONCE_SIZE];
	uint8_t write_counter[4];
	uint8_t address[2];
	uint8_t block_count[2];
	uint8_t op_result[2];
	uint8_t msg_type[2];
};

struct rpmb_req {
	uint16_t cmd;
	uint16_t dev_id;
	uint16_t block_count;
	/* variable length of data */
	/* uint8_t data[]; REMOVED! */
};

#define TEE_RPMB_REQ_DATA(req) \
		((void *)((struct rpmb_req *)(req) + 1))

struct rpmb_raw_data {
	uint16_t msg_type;
	uint16_t *op_result;
	uint16_t *block_count;
	uint16_t *blk_idx;
	uint32_t *write_counter;
	uint8_t *nonce;
	uint8_t *key_mac;
	uint8_t *data;
	/* data length to read or write */
	uint32_t len;
	/* Byte address offset in the first block involved */
	uint8_t byte_offset;
};

#define RPMB_EMMC_CID_SIZE 16
struct rpmb_dev_info {
	uint8_t cid[RPMB_EMMC_CID_SIZE];
	/* EXT CSD-slice 168 "RPMB Size" */
	uint8_t rpmb_size_mult;
	/* EXT CSD-slice 222 "Reliable Write Sector Count" */
	uint8_t rel_wr_sec_c;
	/* Check the ret code and accept the data only if it is OK. */
	uint8_t ret_code;
};

/*
 * Struct for rpmb context data.
 *
 * @key              RPMB key.
 * @cid              eMMC card ID.
 * @hash_ctx_size    Hash context size
 * @wr_cnt           Current write counter.
 * @max_blk_idx      The highest block index supported by current device.
 * @rel_wr_blkcnt    Max number of data blocks for each reliable write.
 * @dev_id           Device ID of the eMMC device.
 * @wr_cnt_synced    Flag indicating if write counter is synced to RPMB.
 * @key_derived      Flag indicating if key has been generated.
 * @key_verified     Flag indicating the key generated is verified ok.
 * @dev_info_synced  Flag indicating if dev info has been retrieved from RPMB.
 */
struct tee_rpmb_ctx {
	uint8_t key[RPMB_KEY_MAC_SIZE];
	uint8_t cid[RPMB_EMMC_CID_SIZE];
	size_t hash_ctx_size;
	uint32_t wr_cnt;
	uint16_t max_blk_idx;
	uint16_t rel_wr_blkcnt;
	uint16_t dev_id;
	bool wr_cnt_synced;
	bool key_derived;
	bool key_verified;
	bool dev_info_synced;
};

static struct tee_rpmb_ctx *rpmb_ctx;

/*
 * Mutex to serialize the operations exported by this file.
 * It protects rpmb_ctx and prevents overlapping operations on eMMC devices with
 * different IDs.
 */
static struct mutex rpmb_mutex = MUTEX_INITIALIZER;

#ifdef CFG_RPMB_TESTKEY

static const uint8_t rpmb_test_key[RPMB_KEY_MAC_SIZE] = {
	0xD3, 0xEB, 0x3E, 0xC3, 0x6E, 0x33, 0x4C, 0x9F,
	0x98, 0x8C, 0xE2, 0xC0, 0xB8, 0x59, 0x54, 0x61,
	0x0D, 0x2B, 0xCF, 0x86, 0x64, 0x84, 0x4D, 0xF2,
	0xAB, 0x56, 0xE6, 0xC6, 0x1B, 0xB7, 0x01, 0xE4
};

static TEE_Result tee_rpmb_key_gen(uint16_t dev_id __unused,
				   uint8_t *key, uint32_t len)
{
	TEE_Result res = TEE_SUCCESS;

	if (!key || RPMB_KEY_MAC_SIZE != len) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	DMSG("RPMB: Using test key");
	memcpy(key, rpmb_test_key, RPMB_KEY_MAC_SIZE);

out:
	return res;
}

#else /* !CFG_RPMB_TESTKEY */

/*
 * NOTE: We need a common API to get hw unique key and it
 * should return error when the hw unique is not a valid
 * one as stated below.
 * We need to make sure the hw unique we get is valid by:
 * 1. In case of HUK is used, checking if OTP is hidden (in
 *    which case only zeros will be returned) or not;
 * 2. In case of SSK is used, checking if SSK in OTP is
 *    write_locked (which means a valid key is provisioned)
 *    or not.
 *
 * Maybe tee_get_hw_unique_key() should be exposed as
 * generic API for getting hw unique key!
 * We should change the API tee_otp_get_hw_unique_key()
 * to return error code!
 */
static TEE_Result tee_get_hw_unique_key(struct tee_hw_unique_key *hwkey)
{
	if (!hwkey)
		return TEE_ERROR_BAD_PARAMETERS;

	tee_otp_get_hw_unique_key(hwkey);

	return TEE_SUCCESS;
}

static TEE_Result tee_rpmb_key_gen(uint16_t dev_id __unused,
				   uint8_t *key, uint32_t len)
{
	TEE_Result res;
	struct tee_hw_unique_key hwkey;
	uint8_t *ctx = NULL;

	if (!key || RPMB_KEY_MAC_SIZE != len) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	IMSG("RPMB: Using generated key");
	res = tee_get_hw_unique_key(&hwkey);
	if (res != TEE_SUCCESS)
		goto out;

	ctx = malloc(rpmb_ctx->hash_ctx_size);
	if (!ctx) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	res = crypto_ops.mac.init(ctx, TEE_ALG_HMAC_SHA256, hwkey.data,
				  HW_UNIQUE_KEY_LENGTH);
	if (res != TEE_SUCCESS)
		goto out;

	res = crypto_ops.mac.update(ctx, TEE_ALG_HMAC_SHA256,
				    (uint8_t *)rpmb_ctx->cid,
				    RPMB_EMMC_CID_SIZE);
	if (res != TEE_SUCCESS)
		goto out;

	res = crypto_ops.mac.final(ctx, TEE_ALG_HMAC_SHA256, key, len);

out:
	free(ctx);
	return res;
}

#endif /* !CFG_RPMB_TESTKEY */

static void u32_to_bytes(uint32_t u32, uint8_t *bytes)
{
	*bytes = (uint8_t) (u32 >> 24);
	*(bytes + 1) = (uint8_t) (u32 >> 16);
	*(bytes + 2) = (uint8_t) (u32 >> 8);
	*(bytes + 3) = (uint8_t) u32;
}

static void bytes_to_u32(uint8_t *bytes, uint32_t *u32)
{
	*u32 = (uint32_t) ((*(bytes) << 24) +
			   (*(bytes + 1) << 16) +
			   (*(bytes + 2) << 8) + (*(bytes + 3)));
}

static void u16_to_bytes(uint16_t u16, uint8_t *bytes)
{
	*bytes = (uint8_t) (u16 >> 8);
	*(bytes + 1) = (uint8_t) u16;
}

static void bytes_to_u16(uint8_t *bytes, uint16_t *u16)
{
	*u16 = (uint16_t) ((*bytes << 8) + *(bytes + 1));
}

static TEE_Result tee_rpmb_mac_calc(uint8_t *mac, uint32_t macsize,
				    uint8_t *key, uint32_t keysize,
				    struct rpmb_data_frame *datafrms,
				    uint16_t blkcnt)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	int i;
	uint8_t *ctx = NULL;

	if (!mac || !key || !datafrms)
		return TEE_ERROR_BAD_PARAMETERS;

	ctx = malloc(rpmb_ctx->hash_ctx_size);
	if (!ctx)
		return TEE_ERROR_OUT_OF_MEMORY;

	res = crypto_ops.mac.init(ctx, TEE_ALG_HMAC_SHA256, key, keysize);
	if (res != TEE_SUCCESS)
		goto func_exit;

	for (i = 0; i < blkcnt; i++) {
		res = crypto_ops.mac.update(ctx, TEE_ALG_HMAC_SHA256,
					  datafrms[i].data,
					  RPMB_MAC_PROTECT_DATA_SIZE);
		if (res != TEE_SUCCESS)
			goto func_exit;
	}

	res = crypto_ops.mac.final(ctx, TEE_ALG_HMAC_SHA256, mac, macsize);
	if (res != TEE_SUCCESS)
		goto func_exit;

	res = TEE_SUCCESS;

func_exit:
	free(ctx);
	return res;
}

struct tee_rpmb_mem {
	paddr_t phreq;
	paddr_t phreq_cookie;
	paddr_t phresp;
	paddr_t phresp_cookie;
	size_t req_size;
	size_t resp_size;
};

static void tee_rpmb_free(struct tee_rpmb_mem *mem)
{
	if (!mem)
		return;

	thread_optee_rpc_free_payload(mem->phreq_cookie);
	thread_optee_rpc_free_payload(mem->phresp_cookie);
	mem->phreq = 0;
	mem->phreq_cookie = 0;
	mem->phresp = 0;
	mem->phresp_cookie = 0;
}


static TEE_Result tee_rpmb_alloc(size_t req_size, size_t resp_size,
		struct tee_rpmb_mem *mem, void **req, void **resp)
{
	TEE_Result res = TEE_SUCCESS;
	size_t req_s = ROUNDUP(req_size, sizeof(uint32_t));
	size_t resp_s = ROUNDUP(resp_size, sizeof(uint32_t));

	if (!mem)
		return TEE_ERROR_BAD_PARAMETERS;

	memset(mem, 0, sizeof(*mem));
	thread_optee_rpc_alloc_payload(req_s,
				       &mem->phreq,
				       &mem->phreq_cookie);
	thread_optee_rpc_alloc_payload(resp_s,
				       &mem->phresp,
				       &mem->phresp_cookie);
	if (!mem->phreq || !mem->phresp) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	if (core_pa2va(mem->phreq, req) || core_pa2va(mem->phresp, resp)) {
		res = TEE_ERROR_GENERIC;
		goto out;
	}

	mem->req_size = req_size;
	mem->resp_size = resp_size;

out:
	if (res != TEE_SUCCESS)
		tee_rpmb_free(mem);
	return res;
}

static TEE_Result tee_rpmb_invoke(struct tee_rpmb_mem *mem)
{
	struct teesmc32_param params[2];

	memset(params, 0, sizeof(params));
	params[0].attr = TEESMC_ATTR_TYPE_MEMREF_INPUT |
			 (TEESMC_ATTR_CACHE_I_WRITE_THR |
				TEESMC_ATTR_CACHE_O_WRITE_THR) <<
					TEESMC_ATTR_CACHE_SHIFT;
	params[1].attr = TEESMC_ATTR_TYPE_MEMREF_OUTPUT |
			 (TEESMC_ATTR_CACHE_I_WRITE_THR |
				TEESMC_ATTR_CACHE_O_WRITE_THR) <<
					TEESMC_ATTR_CACHE_SHIFT;
	params[0].u.memref.buf_ptr = mem->phreq;
	params[0].u.memref.size = mem->req_size;
	params[1].u.memref.buf_ptr = mem->phresp;
	params[1].u.memref.size = mem->resp_size;

	return thread_rpc_cmd(TEE_RPC_RPMB_CMD, 2, params);
}

static bool is_zero(const uint8_t *fek)
{
	int i;

	for (i = 0; i < TEE_FS_KM_FEK_SIZE; i++)
		if (fek[i])
			return false;
	return true;
}

#ifdef CFG_ENC_FS
static TEE_Result encrypt_block(uint8_t *out, const uint8_t *in,
				uint16_t blk_idx, const uint8_t *fek)
{
	return tee_fs_crypt_block(out, in, RPMB_DATA_SIZE, blk_idx, fek,
				  TEE_MODE_ENCRYPT);
}

static TEE_Result decrypt_block(uint8_t *out, const uint8_t *in,
				uint16_t blk_idx, const uint8_t *fek)
{
	return tee_fs_crypt_block(out, in, RPMB_DATA_SIZE, blk_idx, fek,
				  TEE_MODE_DECRYPT);
}
#endif /* CFG_ENC_FS */

/* Decrypt/copy at most one block of data */
static TEE_Result decrypt(uint8_t *out, const struct rpmb_data_frame *frm,
			  size_t size, size_t offset,
			  uint16_t blk_idx __maybe_unused, const uint8_t *fek)
{
	uint8_t *tmp __maybe_unused;

	TEE_ASSERT(size + offset <= RPMB_DATA_SIZE);

	if (!fek) {
		/* Block is not encrypted (not a file data block) */
		memcpy(out, frm->data + offset, size);
	} else if (is_zero(fek)) {
		/*
		 * The file was created with encryption disabled
		 * (CFG_ENC_FS=n)
		 */
#ifdef CFG_ENC_FS
		return TEE_ERROR_SECURITY;
#else
		memcpy(out, frm->data + offset, size);
#endif
	} else {
		/* Block is encrypted */
#ifdef CFG_ENC_FS
		if (size < RPMB_DATA_SIZE) {
			/*
			 * Since output buffer is not large enough to hold one
			 * block we must allocate a temporary buffer.
			 */
			tmp = malloc(RPMB_DATA_SIZE);
			if (!tmp)
				return TEE_ERROR_OUT_OF_MEMORY;
			decrypt_block(tmp, frm->data, blk_idx, fek);
			memcpy(out, tmp + offset, size);
			free(tmp);
		} else {
			TEE_ASSERT(!offset);
			decrypt_block(out, frm->data, blk_idx, fek);
		}
#else
		return TEE_ERROR_SECURITY;
#endif
	}

	return TEE_SUCCESS;
}

static TEE_Result tee_rpmb_req_pack(struct rpmb_req *req,
				    struct rpmb_raw_data *rawdata,
				    uint16_t nbr_frms, uint16_t dev_id,
				    uint8_t *fek __unused)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	int i;
	struct rpmb_data_frame *datafrm;

	if (!req || !rawdata || !nbr_frms)
		return TEE_ERROR_BAD_PARAMETERS;

	/*
	 * Check write blockcount is not bigger than reliable write
	 * blockcount.
	 */
	if ((rawdata->msg_type == RPMB_MSG_TYPE_REQ_AUTH_DATA_WRITE) &&
	    (nbr_frms > rpmb_ctx->rel_wr_blkcnt)) {
		DMSG("wr_blkcnt(%d) > rel_wr_blkcnt(%d)", nbr_frms,
		     rpmb_ctx->rel_wr_blkcnt);
		return TEE_ERROR_GENERIC;
	}

	req->cmd = RPMB_CMD_DATA_REQ;
	req->dev_id = dev_id;

	/* Allocate memory for construct all data packets and calculate MAC. */
	datafrm = calloc(nbr_frms, RPMB_DATA_FRAME_SIZE);
	if (!datafrm)
		return TEE_ERROR_OUT_OF_MEMORY;

	for (i = 0; i < nbr_frms; i++) {
		u16_to_bytes(rawdata->msg_type, datafrm[i].msg_type);

		if (rawdata->block_count)
			u16_to_bytes(*rawdata->block_count,
				     datafrm[i].block_count);

		if (rawdata->blk_idx) {
			/* Check the block index is within range. */
			if ((*rawdata->blk_idx + nbr_frms) >
			    rpmb_ctx->max_blk_idx) {
				res = TEE_ERROR_GENERIC;
				goto func_exit;
			}
			u16_to_bytes(*rawdata->blk_idx, datafrm[i].address);
		}

		if (rawdata->write_counter)
			u32_to_bytes(*rawdata->write_counter,
				     datafrm[i].write_counter);

		if (rawdata->nonce)
			memcpy(datafrm[i].nonce, rawdata->nonce,
			       RPMB_NONCE_SIZE);

		if (rawdata->data) {
#ifdef CFG_ENC_FS
			if (fek)
				encrypt_block(datafrm[i].data,
					rawdata->data + (i * RPMB_DATA_SIZE),
					*rawdata->blk_idx + i, fek);
			else
#endif
				memcpy(datafrm[i].data,
				       rawdata->data + (i * RPMB_DATA_SIZE),
				       RPMB_DATA_SIZE);
		}
	}

	if (rawdata->key_mac) {
		if (rawdata->msg_type == RPMB_MSG_TYPE_REQ_AUTH_DATA_WRITE) {
			res =
			    tee_rpmb_mac_calc(rawdata->key_mac,
					      RPMB_KEY_MAC_SIZE, rpmb_ctx->key,
					      RPMB_KEY_MAC_SIZE, datafrm,
					      nbr_frms);
			if (res != TEE_SUCCESS)
				goto func_exit;
		}
		memcpy(datafrm[nbr_frms - 1].key_mac,
		       rawdata->key_mac, RPMB_KEY_MAC_SIZE);
	}

	memcpy(TEE_RPMB_REQ_DATA(req), datafrm,
	       nbr_frms * RPMB_DATA_FRAME_SIZE);

#ifdef CFG_RPMB_FS_DEBUG_DATA
	for (i = 0; i < nbr_frms; i++) {
		DMSG("Dumping data frame %d:", i);
		DHEXDUMP((uint8_t *)&datafrm[i] + RPMB_STUFF_DATA_SIZE,
			 512 - RPMB_STUFF_DATA_SIZE);
	}
#endif

	res = TEE_SUCCESS;
func_exit:
	free(datafrm);
	return res;
}

static TEE_Result data_cpy_mac_calc_1b(struct rpmb_raw_data *rawdata,
				       struct rpmb_data_frame *frm,
				       uint8_t *fek)
{
	TEE_Result res;
	uint8_t *data;
	uint16_t idx;

	if (rawdata->len + rawdata->byte_offset > RPMB_DATA_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;

	res = tee_rpmb_mac_calc(rawdata->key_mac, RPMB_KEY_MAC_SIZE,
				rpmb_ctx->key, RPMB_KEY_MAC_SIZE, frm, 1);
	if (res != TEE_SUCCESS)
		return res;

	data = rawdata->data;
	bytes_to_u16(frm->address, &idx);

	res = decrypt(data, frm, rawdata->len, rawdata->byte_offset, idx, fek);
	return res;
}

static TEE_Result tee_rpmb_data_cpy_mac_calc(struct rpmb_data_frame *datafrm,
					     struct rpmb_raw_data *rawdata,
					     uint16_t nbr_frms,
					     struct rpmb_data_frame *lastfrm,
					     uint8_t *fek)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	int i;
	uint8_t *ctx = NULL;
	uint16_t offset;
	uint32_t size;
	uint8_t *data;
	uint16_t start_idx;
	struct rpmb_data_frame localfrm;

	if (!datafrm || !rawdata || !nbr_frms || !lastfrm)
		return TEE_ERROR_BAD_PARAMETERS;

	if (nbr_frms == 1)
		return data_cpy_mac_calc_1b(rawdata, lastfrm, fek);

	/* nbr_frms > 1 */

	data = rawdata->data;

	ctx = malloc(rpmb_ctx->hash_ctx_size);
	if (!ctx) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto func_exit;
	}

	res = crypto_ops.mac.init(ctx, TEE_ALG_HMAC_SHA256, rpmb_ctx->key,
				  RPMB_KEY_MAC_SIZE);
	if (res != TEE_SUCCESS)
		goto func_exit;

	/*
	 * Note: JEDEC JESD84-B51: "In every packet the address is the start
	 * address of the full access (not address of the individual half a
	 * sector)"
	 */
	bytes_to_u16(lastfrm->address, &start_idx);

	for (i = 0; i < (nbr_frms - 1); i++) {

		/*
		 * By working on a local copy of the RPMB frame, we ensure that
		 * the data can not be modified after the MAC is computed but
		 * before the payload is decrypted/copied to the output buffer.
		 */
		memcpy(&localfrm, &datafrm[i], RPMB_DATA_FRAME_SIZE);

		res = crypto_ops.mac.update(ctx, TEE_ALG_HMAC_SHA256,
					    localfrm.data,
					    RPMB_MAC_PROTECT_DATA_SIZE);
		if (res != TEE_SUCCESS)
			goto func_exit;

		if (i == 0) {
			/* First block */
			offset = rawdata->byte_offset;
			size = RPMB_DATA_SIZE - offset;
		} else {
			/* Middle blocks */
			size = RPMB_DATA_SIZE;
			offset = 0;
		}

		res = decrypt(data, &localfrm, size, offset, start_idx + i,
			      fek);
		if (res != TEE_SUCCESS)
			goto func_exit;

		data += size;
	}

	/* Last block */
	size = (rawdata->len + rawdata->byte_offset) % RPMB_DATA_SIZE;
	if (size == 0)
		size = RPMB_DATA_SIZE;
	res = decrypt(data, lastfrm, size, 0, start_idx + nbr_frms - 1, fek);
	if (res != TEE_SUCCESS)
		goto func_exit;

	/* Update MAC against the last block */
	res = crypto_ops.mac.update(ctx, TEE_ALG_HMAC_SHA256, lastfrm->data,
				    RPMB_MAC_PROTECT_DATA_SIZE);
	if (res != TEE_SUCCESS)
		goto func_exit;

	res = crypto_ops.mac.final(ctx, TEE_ALG_HMAC_SHA256, rawdata->key_mac,
				   RPMB_KEY_MAC_SIZE);
	if (res != TEE_SUCCESS)
		goto func_exit;

	res = TEE_SUCCESS;

func_exit:
	free(ctx);
	return res;
}

static TEE_Result tee_rpmb_resp_unpack_verify(struct rpmb_data_frame *datafrm,
					      struct rpmb_raw_data *rawdata,
					      uint16_t nbr_frms, uint8_t *fek)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint16_t msg_type;
	uint32_t wr_cnt;
	uint16_t blk_idx;
	uint16_t op_result;
	struct rpmb_data_frame lastfrm;

	if (!datafrm || !rawdata || !nbr_frms)
		return TEE_ERROR_BAD_PARAMETERS;

#ifdef CFG_RPMB_FS_DEBUG_DATA
	for (uint32_t i = 0; i < nbr_frms; i++) {
		DMSG("Dumping data frame %d:", i);
		DHEXDUMP((uint8_t *)&datafrm[i] + RPMB_STUFF_DATA_SIZE,
			 512 - RPMB_STUFF_DATA_SIZE);
	}
#endif

	/* Make sure the last data packet can't be modified once verified */
	memcpy(&lastfrm, &datafrm[nbr_frms - 1], RPMB_DATA_FRAME_SIZE);

	/* Handle operation result and translate to TEEC error code. */
	bytes_to_u16(lastfrm.op_result, &op_result);
	if (rawdata->op_result)
		*rawdata->op_result = op_result;
	if (op_result != RPMB_RESULT_OK)
		return TEE_ERROR_GENERIC;

	/* Check the response msg_type. */
	bytes_to_u16(lastfrm.msg_type, &msg_type);
	if (msg_type != rawdata->msg_type) {
		DMSG("Unexpected msg_type (0x%04x != 0x%04x)", msg_type,
		     rawdata->msg_type);
		return TEE_ERROR_GENERIC;
	}

	if (rawdata->blk_idx) {
		bytes_to_u16(lastfrm.address, &blk_idx);
		if (blk_idx != *rawdata->blk_idx) {
			DMSG("Unexpected block index");
			return TEE_ERROR_GENERIC;
		}
	}

	if (rawdata->write_counter) {
		wr_cnt = *rawdata->write_counter;
		bytes_to_u32(lastfrm.write_counter, rawdata->write_counter);
		if (msg_type == RPMB_MSG_TYPE_RESP_AUTH_DATA_WRITE) {
			/* Verify the write counter is incremented by 1 */
			if (*rawdata->write_counter != wr_cnt + 1) {
				DMSG("Counter mismatched (0x%04x/0x%04x)",
				     *rawdata->write_counter, wr_cnt + 1);
				return TEE_ERROR_SECURITY;
			}
			rpmb_ctx->wr_cnt++;
		}
	}

	if (rawdata->nonce) {
		if (buf_compare_ct(rawdata->nonce, lastfrm.nonce,
				   RPMB_NONCE_SIZE) != 0) {
			DMSG("Nonce mismatched");
			return TEE_ERROR_SECURITY;
		}
	}

	if (rawdata->key_mac) {
		if (msg_type == RPMB_MSG_TYPE_RESP_AUTH_DATA_READ) {
			if (!rawdata->data)
				return TEE_ERROR_GENERIC;

			res = tee_rpmb_data_cpy_mac_calc(datafrm, rawdata,
							 nbr_frms, &lastfrm,
							 fek);

			if (res != TEE_SUCCESS)
				return res;
		} else {
			/*
			 * There should be only one data frame for
			 * other msg types.
			 */
			if (nbr_frms != 1)
				return TEE_ERROR_GENERIC;

			res = tee_rpmb_mac_calc(rawdata->key_mac,
						RPMB_KEY_MAC_SIZE,
						rpmb_ctx->key,
						RPMB_KEY_MAC_SIZE,
						&lastfrm, 1);

			if (res != TEE_SUCCESS)
				return res;
		}

#ifndef CFG_RPMB_FS_NO_MAC
		if (buf_compare_ct(rawdata->key_mac,
				   (datafrm + nbr_frms - 1)->key_mac,
				   RPMB_KEY_MAC_SIZE) != 0) {
			DMSG("MAC mismatched:");
#ifdef CFG_RPMB_FS_DEBUG_DATA
			DHEXDUMP((uint8_t *)rawdata->key_mac, 32);
#endif
			return TEE_ERROR_SECURITY;
		}
#endif /* !CFG_RPMB_FS_NO_MAC */
	}

	return TEE_SUCCESS;
}

static TEE_Result tee_rpmb_get_dev_info(uint16_t dev_id,
					struct rpmb_dev_info *dev_info)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct tee_rpmb_mem mem;
	struct rpmb_dev_info *di;
	struct rpmb_req *req = NULL;
	uint8_t *resp = NULL;
	uint32_t req_size;
	uint32_t resp_size;

	if (!dev_info)
		return TEE_ERROR_BAD_PARAMETERS;

	req_size = sizeof(struct rpmb_req);
	resp_size = sizeof(struct rpmb_dev_info);
	res = tee_rpmb_alloc(req_size, resp_size, &mem,
			     (void *)&req, (void *)&resp);
	if (res != TEE_SUCCESS)
		goto func_exit;

	req->cmd = RPMB_CMD_GET_DEV_INFO;
	req->dev_id = dev_id;

	di = (struct rpmb_dev_info *)resp;
	di->ret_code = RPMB_CMD_GET_DEV_INFO_RET_ERROR;

	res = tee_rpmb_invoke(&mem);
	if (res != TEE_SUCCESS)
		goto func_exit;

	if (di->ret_code != RPMB_CMD_GET_DEV_INFO_RET_OK) {
		res = TEE_ERROR_GENERIC;
		goto func_exit;
	}

	memcpy((uint8_t *)dev_info, resp, sizeof(struct rpmb_dev_info));

#ifdef CFG_RPMB_FS_DEBUG_DATA
	DMSG("Dumping dev_info:");
	DHEXDUMP((uint8_t *)dev_info, sizeof(struct rpmb_dev_info));
#endif

	res = TEE_SUCCESS;

func_exit:
	tee_rpmb_free(&mem);
	return res;
}

static TEE_Result tee_rpmb_init_read_wr_cnt(uint16_t dev_id,
					    uint32_t *wr_cnt,
					    uint16_t *op_result)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct tee_rpmb_mem mem;
	uint16_t msg_type;
	uint8_t nonce[RPMB_NONCE_SIZE];
	uint8_t hmac[RPMB_KEY_MAC_SIZE];
	struct rpmb_req *req = NULL;
	struct rpmb_data_frame *resp = NULL;
	struct rpmb_raw_data rawdata;
	uint32_t req_size;
	uint32_t resp_size;

	if (!wr_cnt)
		return TEE_ERROR_BAD_PARAMETERS;

	req_size = sizeof(struct rpmb_req) + RPMB_DATA_FRAME_SIZE;
	resp_size = RPMB_DATA_FRAME_SIZE;
	res = tee_rpmb_alloc(req_size, resp_size, &mem,
			     (void *)&req, (void *)&resp);
	if (res != TEE_SUCCESS)
		goto func_exit;

	res = crypto_ops.prng.read(nonce, RPMB_NONCE_SIZE);
	if (res != TEE_SUCCESS)
		goto func_exit;

	msg_type = RPMB_MSG_TYPE_REQ_WRITE_COUNTER_VAL_READ;

	memset(&rawdata, 0x00, sizeof(struct rpmb_raw_data));
	rawdata.msg_type = msg_type;
	rawdata.nonce = nonce;

	res = tee_rpmb_req_pack(req, &rawdata, 1, dev_id, NULL);
	if (res != TEE_SUCCESS)
		goto func_exit;

	res = tee_rpmb_invoke(&mem);
	if (res != TEE_SUCCESS)
		goto func_exit;

	msg_type = RPMB_MSG_TYPE_RESP_WRITE_COUNTER_VAL_READ;

	memset(&rawdata, 0x00, sizeof(struct rpmb_raw_data));
	rawdata.msg_type = msg_type;
	rawdata.op_result = op_result;
	rawdata.write_counter = wr_cnt;
	rawdata.nonce = nonce;
	rawdata.key_mac = hmac;

	res = tee_rpmb_resp_unpack_verify(resp, &rawdata, 1, NULL);
	if (res != TEE_SUCCESS)
		goto func_exit;

	res = TEE_SUCCESS;

func_exit:
	tee_rpmb_free(&mem);
	return res;
}

static TEE_Result tee_rpmb_verify_key_sync_counter(uint16_t dev_id)
{
	uint16_t op_result = 0;
	TEE_Result res = TEE_ERROR_GENERIC;

	res = tee_rpmb_init_read_wr_cnt(dev_id, &rpmb_ctx->wr_cnt,
					&op_result);

	if (res == TEE_SUCCESS) {
		rpmb_ctx->key_verified = true;
		rpmb_ctx->wr_cnt_synced = true;
	}

	DMSG("Verify key returning 0x%x\n", res);
	return res;
}

static TEE_Result tee_rpmb_write_key(uint16_t dev_id)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct tee_rpmb_mem mem = { 0 };
	uint16_t msg_type;
	struct rpmb_req *req = NULL;
	struct rpmb_data_frame *resp = NULL;
	struct rpmb_raw_data rawdata;
	uint32_t req_size;
	uint32_t resp_size;

	req_size = sizeof(struct rpmb_req) + RPMB_DATA_FRAME_SIZE;
	resp_size = RPMB_DATA_FRAME_SIZE;
	res = tee_rpmb_alloc(req_size, resp_size, &mem,
			     (void *)&req, (void *)&resp);
	if (res != TEE_SUCCESS)
		goto func_exit;

	msg_type = RPMB_MSG_TYPE_REQ_AUTH_KEY_PROGRAM;

	memset(&rawdata, 0x00, sizeof(struct rpmb_raw_data));
	rawdata.msg_type = msg_type;
	rawdata.key_mac = rpmb_ctx->key;

	res = tee_rpmb_req_pack(req, &rawdata, 1, dev_id, NULL);
	if (res != TEE_SUCCESS)
		goto func_exit;

	res = tee_rpmb_invoke(&mem);
	if (res != TEE_SUCCESS)
		goto func_exit;

	msg_type = RPMB_MSG_TYPE_RESP_AUTH_KEY_PROGRAM;

	memset(&rawdata, 0x00, sizeof(struct rpmb_raw_data));
	rawdata.msg_type = msg_type;

	res = tee_rpmb_resp_unpack_verify(resp, &rawdata, 1, NULL);
	if (res != TEE_SUCCESS)
		goto func_exit;

	res = TEE_SUCCESS;

func_exit:
	tee_rpmb_free(&mem);
	return res;
}

/* True when all the required crypto functions are available */
static bool have_crypto_ops(void)
{
	return (crypto_ops.mac.init && crypto_ops.mac.update &&
		crypto_ops.mac.final && crypto_ops.prng.read);
}

/* This function must never return TEE_SUCCESS if rpmb_ctx == NULL */
static TEE_Result tee_rpmb_init(uint16_t dev_id)
{
	TEE_Result res = TEE_SUCCESS;
	struct rpmb_dev_info dev_info;

	if (!have_crypto_ops())
		return TEE_ERROR_NOT_SUPPORTED;

	if (!rpmb_ctx) {
		rpmb_ctx = calloc(1, sizeof(struct tee_rpmb_ctx));
		if (!rpmb_ctx)
			return TEE_ERROR_OUT_OF_MEMORY;
	} else if (rpmb_ctx->dev_id != dev_id) {
		memset(rpmb_ctx, 0x00, sizeof(struct tee_rpmb_ctx));
	}

	rpmb_ctx->dev_id = dev_id;

	if (!rpmb_ctx->dev_info_synced) {
		DMSG("RPMB: Syncing device information");

		dev_info.rpmb_size_mult = 0;
		dev_info.rel_wr_sec_c = 0;
		res = tee_rpmb_get_dev_info(dev_id, &dev_info);
		if (res != TEE_SUCCESS)
			goto func_exit;

		DMSG("RPMB: RPMB size is %d*128 KB", dev_info.rpmb_size_mult);
		DMSG("RPMB: Reliable Write Sector Count is %d",
		     dev_info.rel_wr_sec_c);

		if (dev_info.rpmb_size_mult == 0) {
			res = TEE_ERROR_GENERIC;
			goto func_exit;
		}

		rpmb_ctx->max_blk_idx = (dev_info.rpmb_size_mult *
					 RPMB_SIZE_SINGLE / RPMB_DATA_SIZE) - 1;

		memcpy(rpmb_ctx->cid, dev_info.cid, RPMB_EMMC_CID_SIZE);

		if ((rpmb_ctx->hash_ctx_size == 0) &&
		    (crypto_ops.mac.get_ctx_size(
			    TEE_ALG_HMAC_SHA256,
			    &rpmb_ctx->hash_ctx_size))) {
			rpmb_ctx->hash_ctx_size = 0;
			res = TEE_ERROR_GENERIC;
			goto func_exit;
		}

#ifdef RPMB_DRIVER_MULTIPLE_WRITE_FIXED
		rpmb_ctx->rel_wr_blkcnt = dev_info.rel_wr_sec_c * 2;
#else
		rpmb_ctx->rel_wr_blkcnt = 1;
#endif

		rpmb_ctx->dev_info_synced = true;
	}

	if (!rpmb_ctx->key_derived) {
		DMSG("RPMB INIT: Deriving key");

		res = tee_rpmb_key_gen(dev_id, rpmb_ctx->key,
				       RPMB_KEY_MAC_SIZE);
		if (res != TEE_SUCCESS)
			goto func_exit;

		rpmb_ctx->key_derived = true;
	}

	/* Perform a write counter read to verify if the key is ok. */
	if (!rpmb_ctx->wr_cnt_synced || !rpmb_ctx->key_verified) {
		DMSG("RPMB INIT: Verifying Key");

		res = tee_rpmb_verify_key_sync_counter(dev_id);
		if (res != TEE_SUCCESS && !rpmb_ctx->key_verified) {
			/*
			 * Need to write the key here and verify it.
			 */
			DMSG("RPMB INIT: Writing Key");
			res = tee_rpmb_write_key(dev_id);
			if (res == TEE_SUCCESS) {
				DMSG("RPMB INIT: Verifying Key");
				res = tee_rpmb_verify_key_sync_counter(dev_id);
			}
		}
	}

func_exit:
	return res;
}

static TEE_Result tee_rpmb_read_unlocked(uint16_t dev_id, uint32_t addr,
					 uint8_t *data, uint32_t len,
					 uint8_t *fek)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct tee_rpmb_mem mem = { 0 };
	uint16_t msg_type;
	uint8_t nonce[RPMB_NONCE_SIZE];
	uint8_t hmac[RPMB_KEY_MAC_SIZE];
	struct rpmb_req *req = NULL;
	struct rpmb_data_frame *resp = NULL;
	struct rpmb_raw_data rawdata;
	uint32_t req_size;
	uint32_t resp_size;
	uint16_t blk_idx;
	uint16_t blkcnt;
	uint8_t byte_offset;

	if (!data || !len)
		return TEE_ERROR_BAD_PARAMETERS;

	blk_idx = addr / RPMB_DATA_SIZE;
	byte_offset = addr % RPMB_DATA_SIZE;

	blkcnt =
	    ROUNDUP(len + byte_offset, RPMB_DATA_SIZE) / RPMB_DATA_SIZE;
	res = tee_rpmb_init(dev_id);
	if (res != TEE_SUCCESS)
		goto func_exit;

	req_size = sizeof(struct rpmb_req) + RPMB_DATA_FRAME_SIZE;
	resp_size = RPMB_DATA_FRAME_SIZE * blkcnt;
	res = tee_rpmb_alloc(req_size, resp_size, &mem,
			     (void *)&req, (void *)&resp);
	if (res != TEE_SUCCESS)
		goto func_exit;

	msg_type = RPMB_MSG_TYPE_REQ_AUTH_DATA_READ;
	res = crypto_ops.prng.read(nonce, RPMB_NONCE_SIZE);
	if (res != TEE_SUCCESS)
		goto func_exit;

	memset(&rawdata, 0x00, sizeof(struct rpmb_raw_data));
	rawdata.msg_type = msg_type;
	rawdata.nonce = nonce;
	rawdata.blk_idx = &blk_idx;
	res = tee_rpmb_req_pack(req, &rawdata, 1, dev_id, NULL);
	if (res != TEE_SUCCESS)
		goto func_exit;

	req->block_count = blkcnt;

	DMSG("Read %u block%s at index %u", blkcnt, ((blkcnt > 1) ? "s" : ""),
	     blk_idx);

	res = tee_rpmb_invoke(&mem);
	if (res != TEE_SUCCESS)
		goto func_exit;

	msg_type = RPMB_MSG_TYPE_RESP_AUTH_DATA_READ;

	memset(&rawdata, 0x00, sizeof(struct rpmb_raw_data));
	rawdata.msg_type = msg_type;
	rawdata.block_count = &blkcnt;
	rawdata.blk_idx = &blk_idx;
	rawdata.nonce = nonce;
	rawdata.key_mac = hmac;
	rawdata.data = data;

	rawdata.len = len;
	rawdata.byte_offset = byte_offset;

	res = tee_rpmb_resp_unpack_verify(resp, &rawdata, blkcnt, fek);
	if (res != TEE_SUCCESS)
		goto func_exit;

	res = TEE_SUCCESS;

func_exit:
	tee_rpmb_free(&mem);
	return res;
}

static TEE_Result tee_rpmb_write_blk(uint16_t dev_id, uint16_t blk_idx,
				     uint8_t *data_blks, uint16_t blkcnt,
				     uint8_t *fek)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct tee_rpmb_mem mem;
	uint16_t msg_type;
	uint32_t wr_cnt;
	uint8_t hmac[RPMB_KEY_MAC_SIZE];
	struct rpmb_req *req = NULL;
	struct rpmb_data_frame *resp = NULL;
	struct rpmb_raw_data rawdata;
	uint32_t req_size;
	uint32_t resp_size;
	uint32_t nbr_writes;
	uint16_t tmp_blkcnt;
	uint16_t tmp_blk_idx;
	uint16_t i;

	DMSG("Write %u block%s at index %u", blkcnt, ((blkcnt > 1) ? "s" : ""),
	     blk_idx);

	if (!data_blks || !blkcnt)
		return TEE_ERROR_BAD_PARAMETERS;

	res = tee_rpmb_init(dev_id);
	if (res != TEE_SUCCESS)
		return res;

	/*
	 * We need to split data when block count
	 * is bigger than reliable block write count.
	 */
	if (blkcnt < rpmb_ctx->rel_wr_blkcnt)
		req_size = sizeof(struct rpmb_req) +
		    RPMB_DATA_FRAME_SIZE * blkcnt;
	else
		req_size = sizeof(struct rpmb_req) +
		    RPMB_DATA_FRAME_SIZE * rpmb_ctx->rel_wr_blkcnt;

	resp_size = RPMB_DATA_FRAME_SIZE;

	nbr_writes = blkcnt / rpmb_ctx->rel_wr_blkcnt;
	if (blkcnt % rpmb_ctx->rel_wr_blkcnt > 0)
		nbr_writes += 1;

	tmp_blkcnt = rpmb_ctx->rel_wr_blkcnt;
	tmp_blk_idx = blk_idx;
	for (i = 0; i < nbr_writes; i++) {
		/*
		 * FIXME:
		 * Re-using mem for several requests causes a kernel crash
		 *
		 *  misc opteearmtz00: Can't find shm for 000000003ef0a000
		 *  kernel BUG at ../optee_linuxdriver/core/tee_supp_com.c:221!
		 */
		res = tee_rpmb_alloc(req_size, resp_size, &mem,
				     (void *)&req, (void *)&resp);
		if (res != TEE_SUCCESS)
			goto func_exit;

		/*
		 * To handle the last write of block count which is
		 * equal or smaller than reliable write block count.
		 */
		if (i == nbr_writes - 1)
			tmp_blkcnt = blkcnt - rpmb_ctx->rel_wr_blkcnt *
			    (nbr_writes - 1);

		msg_type = RPMB_MSG_TYPE_REQ_AUTH_DATA_WRITE;
		wr_cnt = rpmb_ctx->wr_cnt;

		memset(req, 0x00, req_size);
		memset(resp, 0x00, resp_size);

		memset(&rawdata, 0x00, sizeof(struct rpmb_raw_data));
		rawdata.msg_type = msg_type;
		rawdata.block_count = &tmp_blkcnt;
		rawdata.blk_idx = &tmp_blk_idx;
		rawdata.write_counter = &wr_cnt;
		rawdata.key_mac = hmac;
		rawdata.data = data_blks + i * rpmb_ctx->rel_wr_blkcnt *
		    RPMB_DATA_SIZE;

		res = tee_rpmb_req_pack(req, &rawdata, tmp_blkcnt, dev_id,
					fek);
		if (res != TEE_SUCCESS)
			goto free_and_exit;

		res = tee_rpmb_invoke(&mem);
		if (res != TEE_SUCCESS) {
			/*
			 * To force wr_cnt sync next time, as it might get
			 * out of sync due to inconsistent operation result!
			 */
			rpmb_ctx->wr_cnt_synced = false;
			goto free_and_exit;
		}

		msg_type = RPMB_MSG_TYPE_RESP_AUTH_DATA_WRITE;

		memset(&rawdata, 0x00, sizeof(struct rpmb_raw_data));
		rawdata.msg_type = msg_type;
		rawdata.block_count = &tmp_blkcnt;
		rawdata.blk_idx = &tmp_blk_idx;
		rawdata.write_counter = &wr_cnt;
		rawdata.key_mac = hmac;

		res = tee_rpmb_resp_unpack_verify(resp, &rawdata, 1, NULL);
		if (res != TEE_SUCCESS) {
			/*
			 * To force wr_cnt sync next time, as it might get
			 * out of sync due to inconsistent operation result!
			 */
			rpmb_ctx->wr_cnt_synced = false;
			goto free_and_exit;
		}

		tmp_blk_idx += tmp_blkcnt;
		tee_rpmb_free(&mem);
	}

	res = TEE_SUCCESS;
	goto func_exit;

free_and_exit:
	tee_rpmb_free(&mem);
func_exit:
	return res;
}

TEE_Result tee_rpmb_read(uint16_t dev_id, uint32_t addr, uint8_t *data,
			 uint32_t len, uint8_t *fek)
{
	TEE_Result res;

	mutex_lock(&rpmb_mutex);
	res = tee_rpmb_read_unlocked(dev_id, addr, data, len, fek);
	mutex_unlock(&rpmb_mutex);

	return res;
}

bool tee_rpmb_write_is_atomic(uint16_t dev_id __unused, uint32_t addr,
			      uint32_t len)
{
	uint8_t byte_offset = addr % RPMB_DATA_SIZE;
	uint16_t blkcnt = ROUNDUP(len + byte_offset,
				  RPMB_DATA_SIZE) / RPMB_DATA_SIZE;

	return (blkcnt <= rpmb_ctx->rel_wr_blkcnt);
}

TEE_Result tee_rpmb_write(uint16_t dev_id, uint32_t addr, uint8_t *data,
			  uint32_t len, uint8_t *fek)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint8_t *data_tmp = NULL;
	uint16_t blk_idx;
	uint16_t blkcnt;
	uint8_t byte_offset;

	mutex_lock(&rpmb_mutex);

	blk_idx = addr / RPMB_DATA_SIZE;
	byte_offset = addr % RPMB_DATA_SIZE;

	blkcnt =
	    ROUNDUP(len + byte_offset, RPMB_DATA_SIZE) / RPMB_DATA_SIZE;

	if (byte_offset == 0 && (len % RPMB_DATA_SIZE) == 0) {
		res = tee_rpmb_write_blk(dev_id, blk_idx, data, blkcnt, fek);
		if (res != TEE_SUCCESS)
			goto func_exit;
	} else {
		data_tmp = calloc(blkcnt, RPMB_DATA_SIZE);
		if (!data_tmp) {
			res = TEE_ERROR_OUT_OF_MEMORY;
			goto func_exit;
		}

		/* Read the complete blocks */
		res = tee_rpmb_read_unlocked(dev_id, blk_idx * RPMB_DATA_SIZE,
					     data_tmp,
					     blkcnt * RPMB_DATA_SIZE, fek);
		if (res != TEE_SUCCESS)
			goto func_exit;

		/* Partial update of the data blocks */
		memcpy(data_tmp + byte_offset, data, len);

		res = tee_rpmb_write_blk(dev_id, blk_idx, data_tmp, blkcnt,
					 fek);
		if (res != TEE_SUCCESS)
			goto func_exit;
	}

	res = TEE_SUCCESS;

func_exit:
	mutex_unlock(&rpmb_mutex);
	free(data_tmp);
	return res;
}

TEE_Result tee_rpmb_get_write_counter(uint16_t dev_id, uint32_t *counter)
{
	TEE_Result res = TEE_SUCCESS;

	if (!counter)
		return TEE_ERROR_BAD_PARAMETERS;

	mutex_lock(&rpmb_mutex);

	if (!rpmb_ctx || !rpmb_ctx->wr_cnt_synced) {
		res = tee_rpmb_init(dev_id);
		if (res != TEE_SUCCESS)
			goto func_exit;
	}

	*counter = rpmb_ctx->wr_cnt;

func_exit:
	mutex_unlock(&rpmb_mutex);
	return res;
}

TEE_Result tee_rpmb_get_max_block(uint16_t dev_id, uint32_t *max_block)
{
	TEE_Result res = TEE_SUCCESS;

	if (!max_block)
		return TEE_ERROR_BAD_PARAMETERS;

	mutex_lock(&rpmb_mutex);

	if (!rpmb_ctx || !rpmb_ctx->dev_info_synced) {
		res = tee_rpmb_init(dev_id);
		if (res != TEE_SUCCESS)
			goto func_exit;
	}

	*max_block = rpmb_ctx->max_blk_idx;

func_exit:
	mutex_unlock(&rpmb_mutex);
	return res;
}
