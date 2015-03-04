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
#include <kernel/tee_common_otp.h>
#include <kernel/tee_rpc.h>
#include <kernel/thread.h>
#include <kernel/tee_ta_manager.h>
#include <tee/tee_rpmb.h>
#include <kernel/chip_services.h>
#include <kernel/tee_misc.h>
#include <tee/tee_cryp_provider.h>
#include <tee/tee_cryp_utl.h>
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
	uint32_t hash_ctx_size;
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

static TEE_Result mac_calc(uint8_t *mac, uint32_t macsize,
			   uint8_t *data, uint32_t datasize,
			   uint8_t *key __unused, uint32_t keylen __unused)
{
	return tee_hash_createdigest(
		TEE_ALG_HMAC_SHA256, data, datasize, mac, macsize);
}

static TEE_Result mac_init(void *ctx, const uint8_t *key __unused,
			uint32_t keysize __unused)
{
	return crypto_ops.hash.init(ctx, TEE_ALG_HMAC_SHA256);
}

static TEE_Result mac_update(void *ctx, const uint8_t *data, uint32_t datasize)
{
	return crypto_ops.hash.update(ctx, TEE_ALG_HMAC_SHA256, data, datasize);
}

static TEE_Result mac_final(void *ctx, uint8_t *mac, uint32_t macsize)
{
	return crypto_ops.hash.final(ctx, TEE_ALG_HMAC_SHA256, mac, macsize);
}

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
	if (NULL == hwkey)
		return TEE_ERROR_BAD_PARAMETERS;

	tee_otp_get_hw_unique_key(hwkey);

	return TEE_SUCCESS;
}

static TEE_Result tee_rpmb_key_gen(uint16_t dev_id __unused,
				   uint8_t *key, uint32_t len, bool commercial)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct tee_hw_unique_key hwkey;

	if (key == NULL || RPMB_KEY_MAC_SIZE != len)
		return TEE_ERROR_BAD_PARAMETERS;

	if (commercial) {
		res = tee_get_hw_unique_key(&hwkey);
		if (res != TEE_SUCCESS)
			return res;
	} else {
		memset(&hwkey, 0x00, HW_UNIQUE_KEY_LENGTH);
	}

	res = mac_calc((uint8_t *)key, len,
		       (uint8_t *)rpmb_ctx->cid,
		       RPMB_EMMC_CID_SIZE,
		       (uint8_t *)&hwkey, HW_UNIQUE_KEY_LENGTH);
	if (res != TEE_SUCCESS)
		return res;

	return TEE_SUCCESS;
}

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

	if (mac == NULL || key == NULL || datafrms == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	ctx = malloc(rpmb_ctx->hash_ctx_size);
	if (ctx == NULL)
		return TEE_ERROR_OUT_OF_MEMORY;

	res = mac_init(ctx, key, keysize);
	if (res != TEE_SUCCESS)
		goto func_exit;

	for (i = 0; i < blkcnt; i++) {
		res =
		    mac_update(ctx, datafrms[i].data,
			       RPMB_MAC_PROTECT_DATA_SIZE);
		if (res != TEE_SUCCESS)
			goto func_exit;
	}

	res = mac_final(ctx, mac, macsize);
	if (res != TEE_SUCCESS)
		goto func_exit;

	res = TEE_SUCCESS;

func_exit:
	free(ctx);
	return res;
}

struct tee_rpmb_mem {
	struct teesmc32_arg *arg;
	paddr_t pharg;
	paddr_t phpayload;
	paddr_t phreq;
	paddr_t phresp;
	size_t req_size;
	size_t resp_size;
};

static void tee_rpmb_free(struct tee_rpmb_mem *mem)
{
	if (!mem)
		return;

	thread_rpc_free_arg(mem->pharg);
	thread_rpc_free_payload(mem->phpayload);
	mem->pharg = 0;
	mem->phpayload = 0;
}


static TEE_Result tee_rpmb_alloc(size_t req_size, size_t resp_size,
		struct tee_rpmb_mem *mem, void **req, void **resp)
{
	TEE_Result res = TEE_SUCCESS;
	size_t req_s = ROUNDUP(req_size, sizeof(uint32_t));
	size_t resp_s = ROUNDUP(resp_size, sizeof(uint32_t));

	if (!mem)
		return TEE_ERROR_BAD_PARAMETERS;

	mem->pharg = 0;
	mem->phpayload = 0;

	mem->pharg = thread_rpc_alloc_arg(TEESMC32_GET_ARG_SIZE(2));
	mem->phpayload = thread_rpc_alloc_payload(req_s + resp_s);
	if (!mem->pharg || !mem->phpayload) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	mem->phreq = mem->phpayload;
	mem->phresp = mem->phpayload + req_s;

	if (core_pa2va(mem->pharg, &mem->arg) || core_pa2va(mem->phreq, req) ||
	    core_pa2va(mem->phresp, resp)) {
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
	struct teesmc32_param *params;

	memset(mem->arg, 0, TEESMC32_GET_ARG_SIZE(2));

	mem->arg->cmd = TEE_RPC_RPMB_CMD;
	/* In case normal world doesn't update anything */
	mem->arg->ret = TEE_ERROR_GENERIC;

	mem->arg->num_params = 2;
	params = TEESMC32_GET_PARAMS(mem->arg);
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

	thread_rpc_cmd(mem->pharg);
	return mem->arg->ret;
}


static TEE_Result tee_rpmb_req_pack(struct rpmb_req *req,
				    struct rpmb_raw_data *rawdata,
				    uint16_t nbr_frms, uint16_t dev_id)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	int i;
	int j;
	struct rpmb_data_frame *datafrm;

	if (req == NULL || rawdata == NULL || nbr_frms == 0)
		return TEE_ERROR_BAD_PARAMETERS;

	/*
	 * Check write blockcount is not bigger than reliable write
	 * blockcount.
	 */
	if ((rawdata->msg_type == RPMB_MSG_TYPE_REQ_AUTH_DATA_WRITE) &&
	    (nbr_frms > rpmb_ctx->rel_wr_blkcnt)) {
		DMSG("%s: wr_blkcnt(%d) > rel_wr_blkcnt(%d)", __func__,
		     nbr_frms, rpmb_ctx->rel_wr_blkcnt);
		return TEE_ERROR_GENERIC;
	}

	req->cmd = RPMB_CMD_DATA_REQ;
	req->dev_id = dev_id;

	/* Allocate memory for construct all data packets and calculate MAC. */
	datafrm = calloc(nbr_frms, RPMB_DATA_FRAME_SIZE);
	if (datafrm == NULL)
		return TEE_ERROR_OUT_OF_MEMORY;

	for (i = 0; i < nbr_frms; i++) {
		u16_to_bytes(rawdata->msg_type, datafrm[i].msg_type);

		if (rawdata->block_count != NULL)
			u16_to_bytes(*rawdata->block_count,
				     datafrm[i].block_count);

		if (rawdata->blk_idx != NULL) {
			/* Check the block index is within range. */
			if ((*rawdata->blk_idx + nbr_frms) >
			    rpmb_ctx->max_blk_idx) {
				DMSG("%s: blk_idx (%d+%d) > max_blk_idx(%d)",
				     __func__, *rawdata->blk_idx, nbr_frms,
				     rpmb_ctx->max_blk_idx);
				res = TEE_ERROR_GENERIC;
				goto func_exit;
			}
			u16_to_bytes(*rawdata->blk_idx, datafrm[i].address);
		}

		if (rawdata->write_counter != NULL)
			u32_to_bytes(*rawdata->write_counter,
				     datafrm[i].write_counter);

		if (rawdata->nonce != NULL)
			memcpy(datafrm[i].nonce, rawdata->nonce,
			       RPMB_NONCE_SIZE);

		if (rawdata->data != NULL)
			for (j = 0; j < nbr_frms; j++)
				memcpy((datafrm + j)->data,
				       rawdata->data + RPMB_DATA_SIZE * j,
				       RPMB_DATA_SIZE);
	}

	if (rawdata->key_mac != NULL) {
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

#ifdef ENABLE_RPMB_DATA_DUMP
	for (i = 0; i < nbr_frms; i++) {
		DMSG("%s: Dumping datafrm[%d]:", __func__, i);
		HEX_PRINT_BUF((uint8_t *)&datafrm[i] + RPMB_STUFF_DATA_SIZE,
			      512 - RPMB_STUFF_DATA_SIZE);
	}
#endif

	res = TEE_SUCCESS;
func_exit:
	free(datafrm);
	return res;
}

static TEE_Result tee_rpmb_data_cpy_mac_calc(struct rpmb_data_frame *datafrm,
					     struct rpmb_raw_data *rawdata,
					     uint16_t nbr_frms,
					     struct rpmb_data_frame *lastfrm)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	int i;
	uint8_t *ctx = NULL;
	uint16_t offset;
	uint32_t size1;
	uint32_t size2;
	uint8_t *data;

	if (datafrm == NULL || rawdata == NULL ||
	    nbr_frms == 0 || lastfrm == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	data = rawdata->data;

	if (nbr_frms == 1) {
		res = mac_calc(rawdata->key_mac, RPMB_KEY_MAC_SIZE,
			       lastfrm->data, RPMB_MAC_PROTECT_DATA_SIZE,
			       rpmb_ctx->key, RPMB_KEY_MAC_SIZE);
		if (res != TEE_SUCCESS)
			return res;

		memcpy(data, lastfrm->data + rawdata->byte_offset,
		       rawdata->len);
		return TEE_SUCCESS;
	}

	ctx = malloc(rpmb_ctx->hash_ctx_size);
	if (ctx == NULL)
		return TEE_ERROR_OUT_OF_MEMORY;

	res = mac_init(ctx, rpmb_ctx->key, RPMB_KEY_MAC_SIZE);
	if (res != TEE_SUCCESS)
		goto func_exit;

	for (i = 0; i < (nbr_frms - 1); i++) {
		offset = RPMB_DATA_OFFSET;
		size1 = 0;
		size2 = 0;

		if (i == 0) {
			/* Handling the first block */
			if (rawdata->byte_offset != 0) {
				size1 = rawdata->byte_offset;

				res =
				    mac_update(ctx,
					       (uint8_t *)datafrm + offset,
					       size1);
				if (res != TEE_SUCCESS)
					goto func_exit;

				offset += size1;
			}
			size2 = RPMB_DATA_SIZE - rawdata->byte_offset;
		} else {
			/* Handling the middle blocks */
			size2 = RPMB_DATA_SIZE;
		}

		/* Copy the data part for each block. */
		memcpy(data, (uint8_t *)&datafrm[i] + offset, size2);

		/* Calculate HMAC against the data copied. */
		res = mac_update(ctx, (uint8_t *)data, size2);
		if (res != TEE_SUCCESS)
			goto func_exit;

		data += size2;
		offset += size2;

		res = mac_update(ctx, (uint8_t *)&datafrm[i] + offset,
				 RPMB_MAC_PROTECT_DATA_SIZE - (size1 + size2));
		if (res != TEE_SUCCESS)
			goto func_exit;
	}

	/* Copy the data part for the last block. */
	size2 = (rawdata->len + rawdata->byte_offset) % RPMB_DATA_SIZE;
	if (size2 == 0)
		size2 = RPMB_DATA_SIZE;

	memcpy(data, lastfrm->data, size2);

	/* Update MAC against the last block */
	res = mac_update(ctx, lastfrm->data, RPMB_MAC_PROTECT_DATA_SIZE);
	if (res != TEE_SUCCESS)
		goto func_exit;

	res = mac_final(ctx, rawdata->key_mac, RPMB_KEY_MAC_SIZE);
	if (res != TEE_SUCCESS)
		goto func_exit;

	res = TEE_SUCCESS;

func_exit:
	free(ctx);
	return res;
}

static TEE_Result tee_rpmb_resp_unpack_verify(struct rpmb_data_frame *datafrm,
					      struct rpmb_raw_data *rawdata,
					      uint16_t nbr_frms)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint16_t msg_type;
	uint32_t wr_cnt;
	uint16_t blk_idx;
	uint16_t op_result;
	struct rpmb_data_frame lastfrm;

	if (datafrm == NULL || rawdata == NULL || nbr_frms == 0)
		return TEE_ERROR_BAD_PARAMETERS;

#ifdef ENABLE_RPMB_DATA_DUMP
	uint32_t i = 0;
	for (i = 0; i < nbr_frms; i++) {
		DMSG("%s: Dumping datafrm[%d]:", __func__, i);
		HEX_PRINT_BUF((uint8_t *)&datafrm[i] + RPMB_STUFF_DATA_SIZE,
			      512 - RPMB_STUFF_DATA_SIZE);
	}
#endif

	/* Make a secure copy of the last data packet for verification. */
	memcpy(&lastfrm, &datafrm[nbr_frms - 1], RPMB_DATA_FRAME_SIZE);

	/* Handle operation result and translate to TEEC error code. */
	bytes_to_u16(lastfrm.op_result, &op_result);
	if (rawdata->op_result != NULL)
		*rawdata->op_result = op_result;
	if (op_result != RPMB_RESULT_OK) {
		DMSG("%s: op_result != RPMB_RESULT_OK", __func__);
		return TEE_ERROR_GENERIC;
	}

	/* Check the response msg_type. */
	bytes_to_u16(lastfrm.msg_type, &msg_type);
	if (msg_type != rawdata->msg_type) {
		DMSG("%s: Unexpected msg_type", __func__);
		return TEE_ERROR_GENERIC;
	}

	if (rawdata->blk_idx != NULL) {
		bytes_to_u16(lastfrm.address, &blk_idx);
		if (blk_idx != *rawdata->blk_idx) {
			DMSG("%s: Unexpected block index", __func__);
			return TEE_ERROR_GENERIC;
		}
	}

	if (rawdata->write_counter != NULL) {
		wr_cnt = *rawdata->write_counter;
		bytes_to_u32(lastfrm.write_counter, rawdata->write_counter);
		if (msg_type == RPMB_MSG_TYPE_RESP_AUTH_DATA_WRITE) {
			/* Verify the write counter is incremented by 1 */
			if (*rawdata->write_counter != wr_cnt + 1) {
				DMSG("%s: write counter mismatched", __func__);
				return TEE_ERROR_SECURITY;
			}
			rpmb_ctx->wr_cnt++;
		}
	}

	if (rawdata->nonce != NULL) {
		if (buf_compare_ct(rawdata->nonce, lastfrm.nonce,
				   RPMB_NONCE_SIZE) != 0) {
			DMSG("%s: nonce mismatched", __func__);
			return TEE_ERROR_SECURITY;
		}
	}

	if (rawdata->key_mac != NULL) {
		if (msg_type == RPMB_MSG_TYPE_RESP_AUTH_DATA_READ) {
			if (rawdata->data == NULL)
				return TEE_ERROR_GENERIC;

			res = tee_rpmb_data_cpy_mac_calc(datafrm, rawdata,
							 nbr_frms, &lastfrm);
			if (res != TEE_SUCCESS)
				return res;
		} else {
			/*
			 * There should be only one data frame for
			 * other msg types.
			 */
			if (nbr_frms != 1)
				return TEE_ERROR_GENERIC;

			res = mac_calc(rawdata->key_mac, RPMB_KEY_MAC_SIZE,
				       lastfrm.data, RPMB_MAC_PROTECT_DATA_SIZE,
				       rpmb_ctx->key, RPMB_KEY_MAC_SIZE);
			if (res != TEE_SUCCESS)
				return res;
		}

		if (buf_compare_ct(rawdata->key_mac,
				   (datafrm + nbr_frms - 1)->key_mac,
				   RPMB_KEY_MAC_SIZE) != 0) {
			DMSG("%s: MAC mismatched:", __func__);
#ifdef ENABLE_RPMB_DATA_DUMP
			HEX_PRINT_BUF((uint8_t *)rawdata->key_mac, 32);
#endif
			return TEE_ERROR_SECURITY;
		}
	}

	return TEE_SUCCESS;
}

static TEE_Result tee_rpmb_get_dev_info(uint16_t dev_id,
					struct rpmb_dev_info *dev_info)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct tee_rpmb_mem mem;
	struct rpmb_req *req = NULL;
	uint8_t *resp = NULL;
	uint32_t req_size;
	uint32_t resp_size;

	if (dev_info == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	req_size = sizeof(struct rpmb_req);
	resp_size = sizeof(struct rpmb_dev_info);
	res = tee_rpmb_alloc(req_size, resp_size, &mem,
			     (void *)&req, (void *)&resp);
	if (res != TEE_SUCCESS)
		goto func_exit;

	req->cmd = RPMB_CMD_GET_DEV_INFO;
	req->dev_id = dev_id;

	((struct rpmb_dev_info *)resp)->ret_code =
	    RPMB_CMD_GET_DEV_INFO_RET_ERROR;

	res = tee_rpmb_invoke(&mem);
	if (res != TEE_SUCCESS)
		goto func_exit;

	if (((struct rpmb_dev_info *)resp)->ret_code !=
	    RPMB_CMD_GET_DEV_INFO_RET_OK) {
		DMSG("RPMB_CMD_GET_DEV_INFO not OK");
		res = TEE_ERROR_GENERIC;
		goto func_exit;
	}

	memcpy((uint8_t *)dev_info, resp, sizeof(struct rpmb_dev_info));

#ifdef ENABLE_RPMB_DATA_DUMP
	DMSG("Dumping DEV INFO:");
	HEX_PRINT_BUF((uint8_t *)dev_info, sizeof(struct rpmb_dev_info));
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

	if (wr_cnt == NULL)
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

	res = tee_rpmb_req_pack(req, &rawdata, 1, dev_id);
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

	res = tee_rpmb_resp_unpack_verify(resp, &rawdata, 1);
	if (res != TEE_SUCCESS)
		goto func_exit;

	res = TEE_SUCCESS;

func_exit:
	tee_rpmb_free(&mem);
	return res;
}

/*
 * This function must never return TEE_SUCCESS if rpmb_ctx == NULL.
 */
static TEE_Result tee_rpmb_init(uint16_t dev_id, bool writekey, bool commercial)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct rpmb_dev_info dev_info;
	uint16_t op_result;

	if (rpmb_ctx == NULL) {
		rpmb_ctx = calloc(1, sizeof(struct tee_rpmb_ctx));
		if (rpmb_ctx == NULL)
			return TEE_ERROR_OUT_OF_MEMORY;
	} else if (rpmb_ctx->dev_id != dev_id) {
		memset(rpmb_ctx, 0x00, sizeof(struct tee_rpmb_ctx));
	}

	rpmb_ctx->dev_id = dev_id;

	if (!rpmb_ctx->dev_info_synced) {
		dev_info.rpmb_size_mult = 0;
		res = tee_rpmb_get_dev_info(dev_id, &dev_info);
		if (res != TEE_SUCCESS)
			goto func_exit;

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
			    (size_t *)(&rpmb_ctx->hash_ctx_size)))) {
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
		res = tee_rpmb_key_gen(dev_id, rpmb_ctx->key,
				       RPMB_KEY_MAC_SIZE, commercial);
		if (res != TEE_SUCCESS)
			goto func_exit;

		rpmb_ctx->key_derived = true;
	}

	/* Perform a write counter read to verify if the key is ok. */
	if (!rpmb_ctx->wr_cnt_synced || !rpmb_ctx->key_verified) {
		res =
		    tee_rpmb_init_read_wr_cnt(dev_id, &rpmb_ctx->wr_cnt,
					      &op_result);

		if (res == TEE_SUCCESS) {
			rpmb_ctx->key_verified = true;
			rpmb_ctx->wr_cnt_synced = true;

			if (writekey) {
				/*
				 * Return security error here as we SHOULD NOT
				 * allow writing key if the key is already
				 * programmed. This is to prevent leaking the
				 * key which is carried in write key request in
				 * plain text and exposed to normal world during
				 * write key request.
				 */
				res = TEE_ERROR_SECURITY;
			}
		}
	}

func_exit:
	return res;
}

TEE_Result tee_rpmb_write_key(uint16_t dev_id, bool commercial)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct tee_ta_session *sess = NULL;
	struct tee_rpmb_mem mem = { 0 };
	uint16_t msg_type;
	struct rpmb_req *req = NULL;
	struct rpmb_data_frame *resp = NULL;
	struct rpmb_raw_data rawdata;
	uint32_t req_size;
	uint32_t resp_size;

	tee_ta_get_current_session(&sess);
	tee_ta_set_current_session(NULL);

	res = tee_rpmb_init(dev_id, true, commercial);
	if (res != TEE_SUCCESS)
		goto func_exit;

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

	res = tee_rpmb_req_pack(req, &rawdata, 1, dev_id);
	if (res != TEE_SUCCESS)
		goto func_exit;

	res = tee_rpmb_invoke(&mem);
	if (res != TEE_SUCCESS)
		goto func_exit;

	msg_type = RPMB_MSG_TYPE_RESP_AUTH_KEY_PROGRAM;

	memset(&rawdata, 0x00, sizeof(struct rpmb_raw_data));
	rawdata.msg_type = msg_type;

	res = tee_rpmb_resp_unpack_verify(resp, &rawdata, 1);
	if (res != TEE_SUCCESS)
		goto func_exit;

	res = TEE_SUCCESS;

func_exit:
	tee_rpmb_free(&mem);
	tee_ta_set_current_session(sess);
	return res;
}

TEE_Result tee_rpmb_read(uint16_t dev_id,
			 uint32_t addr, uint8_t *data, uint32_t len)
{
	struct tee_ta_session *sess;
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

	if (data == NULL || len == 0)
		return TEE_ERROR_BAD_PARAMETERS;

	tee_ta_get_current_session(&sess);
	tee_ta_set_current_session(NULL);

	blk_idx = addr / RPMB_DATA_SIZE;
	byte_offset = addr % RPMB_DATA_SIZE;

	blkcnt =
	    ROUNDUP(len + byte_offset, RPMB_DATA_SIZE) / RPMB_DATA_SIZE;

	res = tee_rpmb_init(dev_id, false, true);
	if (res != TEE_SUCCESS)
		return res;

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
	res = tee_rpmb_req_pack(req, &rawdata, 1, dev_id);
	if (res != TEE_SUCCESS)
		goto func_exit;

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

	res = tee_rpmb_resp_unpack_verify(resp, &rawdata, blkcnt);
	if (res != TEE_SUCCESS)
		goto func_exit;

	res = TEE_SUCCESS;

func_exit:
	tee_rpmb_free(&mem);
	tee_ta_set_current_session(sess);
	return res;
}

static TEE_Result tee_rpmb_write_blk(uint16_t dev_id,
				     uint16_t blk_idx,
				     uint8_t *data_blks, uint16_t blkcnt)
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

	if (data_blks == NULL || blkcnt == 0)
		return TEE_ERROR_BAD_PARAMETERS;

	res = tee_rpmb_init(dev_id, false, true);
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
	res = tee_rpmb_alloc(req_size, resp_size, &mem,
			     (void *)&req, (void *)&resp);
	if (res != TEE_SUCCESS)
		goto func_exit;

	nbr_writes = blkcnt / rpmb_ctx->rel_wr_blkcnt;
	if (blkcnt % rpmb_ctx->rel_wr_blkcnt > 0)
		nbr_writes += 1;

	tmp_blkcnt = rpmb_ctx->rel_wr_blkcnt;
	tmp_blk_idx = blk_idx;
	for (i = 0; i < nbr_writes; i++) {
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

		res = tee_rpmb_req_pack(req, &rawdata, tmp_blkcnt, dev_id);
		if (res != TEE_SUCCESS)
			goto func_exit;

		res = tee_rpmb_invoke(&mem);
		if (res != TEE_SUCCESS) {
			/*
			 * To force wr_cnt sync next time, as it might get
			 * out of sync due to inconsistent operation result!
			 */
			rpmb_ctx->wr_cnt_synced = false;
			goto func_exit;
		}

		msg_type = RPMB_MSG_TYPE_RESP_AUTH_DATA_WRITE;

		memset(&rawdata, 0x00, sizeof(struct rpmb_raw_data));
		rawdata.msg_type = msg_type;
		rawdata.block_count = &tmp_blkcnt;
		rawdata.blk_idx = &tmp_blk_idx;
		rawdata.write_counter = &wr_cnt;
		rawdata.key_mac = hmac;

		res = tee_rpmb_resp_unpack_verify(resp, &rawdata, 1);
		if (res != TEE_SUCCESS) {
			/*
			 * To force wr_cnt sync next time, as it might get
			 * out of sync due to inconsistent operation result!
			 */
			rpmb_ctx->wr_cnt_synced = false;
			goto func_exit;
		}

		tmp_blk_idx += tmp_blkcnt;
	}

	res = TEE_SUCCESS;

func_exit:
	tee_rpmb_free(&mem);
	return res;
}

TEE_Result tee_rpmb_write(uint16_t dev_id,
			  uint32_t addr, uint8_t *data, uint32_t len)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct tee_ta_session *sess;
	uint8_t *data_tmp = NULL;
	uint16_t blk_idx;
	uint16_t blkcnt;
	uint8_t byte_offset;

	tee_ta_get_current_session(&sess);
	tee_ta_set_current_session(NULL);

	blk_idx = addr / RPMB_DATA_SIZE;
	byte_offset = addr % RPMB_DATA_SIZE;

	blkcnt =
	    ROUNDUP(len + byte_offset, RPMB_DATA_SIZE) / RPMB_DATA_SIZE;

	if (byte_offset == 0 && (len % RPMB_DATA_SIZE) == 0) {
		res = tee_rpmb_write_blk(dev_id, blk_idx, data, blkcnt);
		if (res != TEE_SUCCESS)
			goto func_exit;
	} else {
		data_tmp = calloc(blkcnt, RPMB_DATA_SIZE);
		if (data_tmp == NULL)
			return TEE_ERROR_OUT_OF_MEMORY;

		/* Read the complete blocks */
		res = tee_rpmb_read(dev_id, blk_idx * RPMB_DATA_SIZE,
				    data_tmp, blkcnt * RPMB_DATA_SIZE);
		if (res != TEE_SUCCESS)
			goto func_exit;

		/* Partial update of the data blocks */
		memcpy(data_tmp + byte_offset, data, len);

		res = tee_rpmb_write_blk(dev_id, blk_idx, data_tmp, blkcnt);
		if (res != TEE_SUCCESS)
			goto func_exit;
	}

	res = TEE_SUCCESS;

func_exit:
	free(data_tmp);
	tee_ta_set_current_session(sess);
	return res;
}

TEE_Result tee_rpmb_get_write_counter(uint16_t dev_id, uint32_t *counter)
{
	TEE_Result res;
	struct tee_ta_session *sess;

	if (counter == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	tee_ta_get_current_session(&sess);
	tee_ta_set_current_session(NULL);

	if (rpmb_ctx == NULL || !rpmb_ctx->wr_cnt_synced) {
		res = tee_rpmb_init(dev_id, false, true);
		if (res != TEE_SUCCESS)
			return res;
	}

	*counter = rpmb_ctx->wr_cnt;

	tee_ta_set_current_session(sess);
	return TEE_SUCCESS;
}
