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

#include <assert.h>
#include <kernel/tee_common.h>
#include <kernel/handle.h>
#include <kernel/mutex.h>
#include <kernel/tee_common_otp.h>
#include <kernel/thread.h>
#include <optee_msg.h>
#include <tee/tee_cryp_provider.h>
#include <tee/tee_fs_defs.h>
#include <tee/tee_fs.h>
#include <tee/tee_fs_key_manager.h>
#include <mm/core_memprot.h>
#include <mm/tee_mm.h>
#include <stdlib.h>
#include <string.h>
#include <string_ext.h>
#include <sys/queue.h>
#include <trace.h>
#include <util.h>

#define RPMB_STORAGE_START_ADDRESS      0
#define RPMB_FS_FAT_START_ADDRESS       512
#define RPMB_BLOCK_SIZE_SHIFT           8

#define RPMB_FS_MAGIC                   0x52504D42
#define FS_VERSION                      2
#define N_ENTRIES                       8

#define FILE_IS_ACTIVE                  (1u << 0)
#define FILE_IS_LAST_ENTRY              (1u << 1)

#define TEE_RPMB_FS_FILENAME_LENGTH 224

struct tee_rpmb_fs_stat {
	size_t size;
	uint32_t reserved;
};

/**
 * FS parameters: Information often used by internal functions.
 * fat_start_address will be set by rpmb_fs_setup().
 * rpmb_fs_parameters can be read by any other function.
 */
struct rpmb_fs_parameters {
	uint32_t fat_start_address;
	uint32_t max_rpmb_address;
};

/**
 * File entry for a single file in a RPMB_FS partition.
 */
struct rpmb_fat_entry {
	uint32_t start_address;
	uint32_t data_size;
	uint32_t flags;
	uint32_t write_counter;
	uint8_t fek[TEE_FS_KM_FEK_SIZE];
	char filename[TEE_RPMB_FS_FILENAME_LENGTH];
};

/**
 * FAT entry context with reference to a FAT entry and its
 * location in RPMB.
 */
struct rpmb_file_handle {
	struct rpmb_fat_entry fat_entry;
	char filename[TEE_RPMB_FS_FILENAME_LENGTH];
	/* Address for current entry in RPMB */
	uint32_t rpmb_fat_address;
	/* Current position */
	uint32_t pos;
	uint32_t flags;
};

/**
 * RPMB_FS partition data
 */
struct rpmb_fs_partition {
	uint32_t rpmb_fs_magic;
	uint32_t fs_version;
	uint32_t write_counter;
	uint32_t fat_start_address;
	/* Do not use reserved[] for other purpose than partition data. */
	uint8_t reserved[112];
};

/**
 * A node in a list of directory entries. entry->name is a
 * pointer to name here.
 */
struct tee_rpmb_fs_dirent {
	struct tee_fs_dirent entry;
	char name[TEE_RPMB_FS_FILENAME_LENGTH];
	/* */
	SIMPLEQ_ENTRY(tee_rpmb_fs_dirent) link;
};

/**
 * The RPMB directory representation. It contains a queue of
 * RPMB directory entries: 'next'.
 * The current pointer points to the last directory entry
 * returned by readdir().
 */
struct tee_fs_dir {
	struct tee_rpmb_fs_dirent *current;
	/* */
	SIMPLEQ_HEAD(next_head, tee_rpmb_fs_dirent) next;
};

static struct rpmb_fs_parameters *fs_par;

static struct handle_db fs_handle_db = HANDLE_DB_INITIALIZER;

/*
 * Lower interface to RPMB device
 */

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
	uint64_t phreq_cookie;
	paddr_t phresp;
	uint64_t phresp_cookie;
	size_t req_size;
	size_t resp_size;
};

static void tee_rpmb_free(struct tee_rpmb_mem *mem)
{
	if (!mem)
		return;

	thread_rpc_free_payload(mem->phreq_cookie);
	thread_rpc_free_payload(mem->phresp_cookie);
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
	thread_rpc_alloc_payload(req_s, &mem->phreq, &mem->phreq_cookie);
	thread_rpc_alloc_payload(resp_s, &mem->phresp, &mem->phresp_cookie);
	if (!mem->phreq || !mem->phresp) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	*req = phys_to_virt(mem->phreq, MEM_AREA_NSEC_SHM);
	*resp = phys_to_virt(mem->phresp, MEM_AREA_NSEC_SHM);
	if (!*req || !*resp) {
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
	struct optee_msg_param params[2];

	memset(params, 0, sizeof(params));
	params[0].attr = OPTEE_MSG_ATTR_TYPE_TMEM_INPUT;
	params[1].attr = OPTEE_MSG_ATTR_TYPE_TMEM_OUTPUT;
	params[0].u.tmem.buf_ptr = mem->phreq;
	params[0].u.tmem.size = mem->req_size;
	params[0].u.tmem.shm_ref = mem->phreq_cookie;
	params[1].u.tmem.buf_ptr = mem->phresp;
	params[1].u.tmem.size = mem->resp_size;
	params[1].u.tmem.shm_ref = mem->phresp_cookie;

	return thread_rpc_cmd(OPTEE_MSG_RPC_CMD_RPMB, 2, params);
}

static bool is_zero(const uint8_t *buf, size_t size)
{
	size_t i;

	for (i = 0; i < size; i++)
		if (buf[i])
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
	} else if (is_zero(fek, TEE_FS_KM_FEK_SIZE)) {
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
				    const uint8_t *fek __unused)
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
				     const uint8_t *data_blks, uint16_t blkcnt,
				     const uint8_t *fek)
{
	TEE_Result res;
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
	res = tee_rpmb_alloc(req_size, resp_size, &mem,
			     (void *)&req, (void *)&resp);
	if (res != TEE_SUCCESS)
		return res;

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
		rawdata.data = (uint8_t *)data_blks +
				i * rpmb_ctx->rel_wr_blkcnt * RPMB_DATA_SIZE;

		res = tee_rpmb_req_pack(req, &rawdata, tmp_blkcnt, dev_id,
					fek);
		if (res != TEE_SUCCESS)
			goto out;

		res = tee_rpmb_invoke(&mem);
		if (res != TEE_SUCCESS) {
			/*
			 * To force wr_cnt sync next time, as it might get
			 * out of sync due to inconsistent operation result!
			 */
			rpmb_ctx->wr_cnt_synced = false;
			goto out;
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
			goto out;
		}

		tmp_blk_idx += tmp_blkcnt;
	}

out:
	tee_rpmb_free(&mem);
	return res;
}

/*
 * Read RPMB data in bytes.
 *
 * @dev_id     Device ID of the eMMC device.
 * @addr       Byte address of data.
 * @data       Pointer to the data.
 * @len        Size of data in bytes.
 * @fek        SSK-encrypted File Encryption Key or NULL.
 */
static TEE_Result tee_rpmb_read(uint16_t dev_id, uint32_t addr, uint8_t *data,
				uint32_t len, uint8_t *fek)
{
	TEE_Result res;

	mutex_lock(&rpmb_mutex);
	res = tee_rpmb_read_unlocked(dev_id, addr, data, len, fek);
	mutex_unlock(&rpmb_mutex);

	return res;
}

static bool tee_rpmb_write_is_atomic(uint16_t dev_id __unused, uint32_t addr,
				     uint32_t len)
{
	uint8_t byte_offset = addr % RPMB_DATA_SIZE;
	uint16_t blkcnt = ROUNDUP(len + byte_offset,
				  RPMB_DATA_SIZE) / RPMB_DATA_SIZE;

	return (blkcnt <= rpmb_ctx->rel_wr_blkcnt);
}

/*
 * Write RPMB data in bytes.
 *
 * @dev_id     Device ID of the eMMC device.
 * @addr       Byte address of data.
 * @data       Pointer to the data.
 * @len        Size of data in bytes.
 * @fek        SSK-encrypted File Encryption Key or NULL.
 */
static TEE_Result tee_rpmb_write(uint16_t dev_id, uint32_t addr,
				 const uint8_t *data, uint32_t len,
				 uint8_t *fek)
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

/*
 * Read the RPMB write counter.
 *
 * @dev_id     Device ID of the eMMC device.
 * @counter    Pointer to the counter.
 */
static TEE_Result tee_rpmb_get_write_counter(uint16_t dev_id,
					     uint32_t *counter)
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

/*
 * Read the RPMB max block.
 *
 * @dev_id     Device ID of the eMMC device.
 * @counter    Pointer to receive the max block.
 */
static TEE_Result tee_rpmb_get_max_block(uint16_t dev_id, uint32_t *max_block)
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

/*
 * End of lower interface to RPMB device
 */

static TEE_Result get_fat_start_address(uint32_t *addr);

static void dump_fat(void)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct rpmb_fat_entry *fat_entries = NULL;
	uint32_t fat_address;
	size_t size;
	int i;
	bool last_entry_found = false;

	res = get_fat_start_address(&fat_address);
	if (res != TEE_SUCCESS)
		goto out;

	size = N_ENTRIES * sizeof(struct rpmb_fat_entry);
	fat_entries = malloc(size);
	if (!fat_entries) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	while (!last_entry_found) {
		res = tee_rpmb_read(CFG_RPMB_FS_DEV_ID, fat_address,
				    (uint8_t *)fat_entries, size, NULL);
		if (res != TEE_SUCCESS)
			goto out;

		for (i = 0; i < N_ENTRIES; i++) {

			FMSG("flags 0x%x, size %d, address 0x%x, filename '%s'",
				fat_entries[i].flags,
				fat_entries[i].data_size,
				fat_entries[i].start_address,
				fat_entries[i].filename);

			if ((fat_entries[i].flags & FILE_IS_LAST_ENTRY) != 0) {
				last_entry_found = true;
				break;
			}

			/* Move to next fat_entry. */
			fat_address += sizeof(struct rpmb_fat_entry);
		}
	}

out:
	free(fat_entries);
}

#if (TRACE_LEVEL >= TRACE_DEBUG)
static void dump_fh(struct rpmb_file_handle *fh)
{
	DMSG("fh->filename=%s", fh->filename);
	DMSG("fh->pos=%u", fh->pos);
	DMSG("fh->rpmb_fat_address=%u", fh->rpmb_fat_address);
	DMSG("fh->fat_entry.start_address=%u", fh->fat_entry.start_address);
	DMSG("fh->fat_entry.data_size=%u", fh->fat_entry.data_size);
}
#else
static void dump_fh(struct rpmb_file_handle *fh __unused)
{
}
#endif

static struct rpmb_file_handle *alloc_file_handle(const char *filename)
{
	struct rpmb_file_handle *fh = NULL;

	fh = calloc(1, sizeof(struct rpmb_file_handle));
	if (!fh)
		return NULL;

	if (filename)
		strlcpy(fh->filename, filename, sizeof(fh->filename));

	return fh;
}

/**
 * write_fat_entry: Store info in a fat_entry to RPMB.
 */
static TEE_Result write_fat_entry(struct rpmb_file_handle *fh,
				  bool update_write_counter)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	/* Protect partition data. */
	if (fh->rpmb_fat_address < sizeof(struct rpmb_fs_partition)) {
		res = TEE_ERROR_ACCESS_CONFLICT;
		goto out;
	}

	if (fh->rpmb_fat_address % sizeof(struct rpmb_fat_entry) != 0) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	if (update_write_counter) {
		res = tee_rpmb_get_write_counter(CFG_RPMB_FS_DEV_ID,
						 &fh->fat_entry.write_counter);
		if (res != TEE_SUCCESS)
			goto out;
	}

	res = tee_rpmb_write(CFG_RPMB_FS_DEV_ID, fh->rpmb_fat_address,
			     (uint8_t *)&fh->fat_entry,
			     sizeof(struct rpmb_fat_entry), NULL);

	dump_fat();

out:
	return res;
}

/**
 * rpmb_fs_setup: Setup rpmb fs.
 * Set initial partition and FS values and write to RPMB.
 * Store frequently used data in RAM.
 */
static TEE_Result rpmb_fs_setup(void)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct rpmb_fs_partition *partition_data = NULL;
	struct rpmb_file_handle *fh = NULL;
	uint32_t max_rpmb_block = 0;

	if (fs_par) {
		res = TEE_SUCCESS;
		goto out;
	}

	res = tee_rpmb_get_max_block(CFG_RPMB_FS_DEV_ID, &max_rpmb_block);
	if (res != TEE_SUCCESS)
		goto out;

	partition_data = calloc(1, sizeof(struct rpmb_fs_partition));
	if (!partition_data) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	res = tee_rpmb_read(CFG_RPMB_FS_DEV_ID, RPMB_STORAGE_START_ADDRESS,
			    (uint8_t *)partition_data,
			    sizeof(struct rpmb_fs_partition), NULL);
	if (res != TEE_SUCCESS)
		goto out;

#ifndef CFG_RPMB_RESET_FAT
	if (partition_data->rpmb_fs_magic == RPMB_FS_MAGIC) {
		if (partition_data->fs_version == FS_VERSION) {
			res = TEE_SUCCESS;
			goto store_fs_par;
		} else {
			/* Wrong software is in use. */
			res = TEE_ERROR_ACCESS_DENIED;
			goto out;
		}
	}
#else
	EMSG("**** Clearing Storage ****");
#endif

	/* Setup new partition data. */
	partition_data->rpmb_fs_magic = RPMB_FS_MAGIC;
	partition_data->fs_version = FS_VERSION;
	partition_data->fat_start_address = RPMB_FS_FAT_START_ADDRESS;

	/* Initial FAT entry with FILE_IS_LAST_ENTRY flag set. */
	fh = alloc_file_handle(NULL);
	if (!fh) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}
	fh->fat_entry.flags = FILE_IS_LAST_ENTRY;
	fh->rpmb_fat_address = partition_data->fat_start_address;

	/* Write init FAT entry and partition data to RPMB. */
	res = write_fat_entry(fh, true);
	if (res != TEE_SUCCESS)
		goto out;

	res =
	    tee_rpmb_get_write_counter(CFG_RPMB_FS_DEV_ID,
				       &partition_data->write_counter);
	if (res != TEE_SUCCESS)
		goto out;
	res = tee_rpmb_write(CFG_RPMB_FS_DEV_ID, RPMB_STORAGE_START_ADDRESS,
			     (uint8_t *)partition_data,
			     sizeof(struct rpmb_fs_partition), NULL);

#ifndef CFG_RPMB_RESET_FAT
store_fs_par:
#endif

	/* Store FAT start address. */
	fs_par = calloc(1, sizeof(struct rpmb_fs_parameters));
	if (!fs_par) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	fs_par->fat_start_address = partition_data->fat_start_address;
	fs_par->max_rpmb_address = max_rpmb_block << RPMB_BLOCK_SIZE_SHIFT;

	dump_fat();

out:
	free(fh);
	free(partition_data);
	return res;
}

/**
 * get_fat_start_address:
 * FAT start_address from fs_par.
 */
static TEE_Result get_fat_start_address(uint32_t *addr)
{
	if (!fs_par)
		return TEE_ERROR_NO_DATA;

	*addr = fs_par->fat_start_address;

	return TEE_SUCCESS;
}

/**
 * read_fat: Read FAT entries
 * Return matching FAT entry for read, rm rename and stat.
 * Build up memory pool and return matching entry for write operation.
 * "Last FAT entry" can be returned during write.
 */
static TEE_Result read_fat(struct rpmb_file_handle *fh, tee_mm_pool_t *p)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	tee_mm_entry_t *mm = NULL;
	struct rpmb_fat_entry *fat_entries = NULL;
	uint32_t fat_address;
	size_t size;
	int i;
	bool entry_found = false;
	bool last_entry_found = false;
	bool expand_fat = false;
	struct rpmb_file_handle last_fh;

	DMSG("fat_address %d", fh->rpmb_fat_address);

	res = rpmb_fs_setup();
	if (res != TEE_SUCCESS)
		goto out;

	res = get_fat_start_address(&fat_address);
	if (res != TEE_SUCCESS)
		goto out;

	size = N_ENTRIES * sizeof(struct rpmb_fat_entry);
	fat_entries = malloc(size);
	if (!fat_entries) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	/*
	 * The pool is used to represent the current RPMB layout. To find
	 * a slot for the file tee_mm_alloc is called on the pool. Thus
	 * if it is not NULL the entire FAT must be traversed to fill in
	 * the pool.
	 */
	while (!last_entry_found && (!entry_found || p)) {
		res = tee_rpmb_read(CFG_RPMB_FS_DEV_ID, fat_address,
				    (uint8_t *)fat_entries, size, NULL);
		if (res != TEE_SUCCESS)
			goto out;

		for (i = 0; i < N_ENTRIES; i++) {
			/*
			 * Look for an entry, matching filenames. (read, rm,
			 * rename and stat.). Only store first filename match.
			 */
			if (fh->filename &&
			    (strcmp(fh->filename,
				    fat_entries[i].filename) == 0) &&
			    (fat_entries[i].flags & FILE_IS_ACTIVE) &&
			    (!entry_found)) {
				entry_found = true;
				fh->rpmb_fat_address = fat_address;
				memcpy(&fh->fat_entry, &fat_entries[i],
				       sizeof(struct rpmb_fat_entry));
				if (!p)
					break;
			}

			/* Add existing files to memory pool. (write) */
			if (p) {
				if ((fat_entries[i].flags & FILE_IS_ACTIVE) &&
				    (fat_entries[i].data_size > 0)) {

					mm = tee_mm_alloc2
						(p,
						 fat_entries[i].start_address,
						 fat_entries[i].data_size);
					if (!mm) {
						res = TEE_ERROR_OUT_OF_MEMORY;
						goto out;
					}
				}

				/* Unused FAT entries can be reused (write) */
				if (((fat_entries[i].flags & FILE_IS_ACTIVE) ==
				     0) && (fh->rpmb_fat_address == 0)) {
					fh->rpmb_fat_address = fat_address;
					memcpy(&fh->fat_entry, &fat_entries[i],
					       sizeof(struct rpmb_fat_entry));
				}
			}

			if ((fat_entries[i].flags & FILE_IS_LAST_ENTRY) != 0) {
				last_entry_found = true;

				/*
				 * If the last entry was reached and was chosen
				 * by the previous check, then the FAT needs to
				 * be expanded.
				 * fh->rpmb_fat_address is the address chosen
				 * to store the files FAT entry and fat_address
				 * is the current FAT entry address being
				 * compared.
				 */
				if (p && fh->rpmb_fat_address == fat_address)
					expand_fat = true;
				break;
			}

			/* Move to next fat_entry. */
			fat_address += sizeof(struct rpmb_fat_entry);
		}
	}

	/*
	 * Represent the FAT table in the pool.
	 */
	if (p) {
		/*
		 * Since fat_address is the start of the last entry it needs to
		 * be moved up by an entry.
		 */
		fat_address += sizeof(struct rpmb_fat_entry);

		/* Make room for yet a FAT entry and add to memory pool. */
		if (expand_fat)
			fat_address += sizeof(struct rpmb_fat_entry);

		mm = tee_mm_alloc2(p, RPMB_STORAGE_START_ADDRESS, fat_address);
		if (!mm) {
			res = TEE_ERROR_OUT_OF_MEMORY;
			goto out;
		}

		if (expand_fat) {
			/*
			 * Point fat_address to the beginning of the new
			 * entry.
			 */
			fat_address -= sizeof(struct rpmb_fat_entry);
			memset(&last_fh, 0, sizeof(last_fh));
			last_fh.fat_entry.flags = FILE_IS_LAST_ENTRY;
			last_fh.rpmb_fat_address = fat_address;
			res = write_fat_entry(&last_fh, true);
			if (res != TEE_SUCCESS)
				goto out;
		}
	}

	if (fh->filename && !fh->rpmb_fat_address)
		res = TEE_ERROR_FILE_NOT_FOUND;

out:
	free(fat_entries);
	return res;
}

#ifdef CFG_ENC_FS
static TEE_Result generate_fek(struct rpmb_fat_entry *fe)
{
	TEE_Result res;

again:
	res = crypto_ops.prng.read(fe->fek, sizeof(fe->fek));
	if (res != TEE_SUCCESS)
		return res;

	if (is_zero(fe->fek, sizeof(fe->fek)))
		goto again;

	return res;
}
#else
static TEE_Result generate_fek(struct rpmb_fat_entry *fe)
{
	memset(fe->fek, 0, sizeof(fe->fek));
	return TEE_SUCCESS;
}
#endif

static int rpmb_fs_open_internal(const char *file, int flags, ...)
{
	int fd = -1;
	struct rpmb_file_handle *fh = NULL;
	size_t filelen;
	tee_mm_pool_t p;
	bool pool_result;
	TEE_Result res = TEE_ERROR_GENERIC;

	if (!file) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	filelen = strlen(file);
	if (filelen >= TEE_RPMB_FS_FILENAME_LENGTH - 1 || filelen == 0) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	if (file[filelen - 1] == '/') {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	fh = alloc_file_handle(file);
	if (!fh) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	/* We need to do setup in order to make sure fs_par is filled in */
	res = rpmb_fs_setup();
	if (res != TEE_SUCCESS)
		goto out;

	if (flags & TEE_FS_O_CREATE) {
		/* Upper memory allocation must be used for RPMB_FS. */
		pool_result = tee_mm_init(&p,
					  RPMB_STORAGE_START_ADDRESS,
					  fs_par->max_rpmb_address,
					  RPMB_BLOCK_SIZE_SHIFT,
					  TEE_MM_POOL_HI_ALLOC);

		if (!pool_result) {
			res = TEE_ERROR_OUT_OF_MEMORY;
			goto out;
		}

		res = read_fat(fh, &p);
		tee_mm_final(&p);
		if (res != TEE_SUCCESS)
			goto out;
	} else {
		res = read_fat(fh, NULL);
		if (res != TEE_SUCCESS)
			goto out;
	}

	/* Add the handle to the db */
	fd = handle_get(&fs_handle_db, fh);
	if (fd == -1) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	/*
	 * If this is opened with create and the entry found was not active
	 * then this is a new file and the FAT entry must be written
	 */
	if (flags & TEE_FS_O_CREATE) {
		if ((fh->fat_entry.flags & FILE_IS_ACTIVE) == 0) {
			memset(&fh->fat_entry, 0,
				sizeof(struct rpmb_fat_entry));
			memcpy(fh->fat_entry.filename, file, strlen(file));
			/* Start address and size are 0 */
			fh->fat_entry.flags = FILE_IS_ACTIVE;

			res = generate_fek(&fh->fat_entry);
			if (res != TEE_SUCCESS) {
				handle_put(&fs_handle_db, fd);
				fd = -1;
				goto out;
			}
			DMSG("GENERATE FEK key: %p",
			     (void *)fh->fat_entry.fek);
			DHEXDUMP(fh->fat_entry.fek, sizeof(fh->fat_entry.fek));

			res = write_fat_entry(fh, true);
			if (res != TEE_SUCCESS) {
				handle_put(&fs_handle_db, fd);
				fd = -1;
				goto out;
			}
		}
	}

	res = TEE_SUCCESS;
	fh->flags = flags;

out:
	if (res != TEE_SUCCESS) {
		if (fh)
			free(fh);

		fd = -1;
	}

	return fd;
}

static int rpmb_fs_close(int fd)
{
	struct rpmb_file_handle *fh;

	fh = handle_put(&fs_handle_db, fd);
	if (fh) {
		free(fh);
		return 0;
	}

	return -1;
}

static int rpmb_fs_read(TEE_Result *errno, int fd, void *buf, size_t size)
{
	TEE_Result res;
	struct rpmb_file_handle *fh;
	int read_size = -1;

	if (!size)
		return 0;

	if (!buf) {
		*errno = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	fh = handle_lookup(&fs_handle_db, fd);
	if (!fh) {
		*errno = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}
	dump_fh(fh);

	res = read_fat(fh, NULL);
	if (res != TEE_SUCCESS) {
		*errno = res;
		goto out;
	}

	size = MIN(size, fh->fat_entry.data_size - fh->pos);
	if (size > 0) {
		res = tee_rpmb_read(CFG_RPMB_FS_DEV_ID,
				    fh->fat_entry.start_address + fh->pos, buf,
				    size, fh->fat_entry.fek);
		if (res != TEE_SUCCESS) {
			*errno = res;
			goto out;
		}
	}
	read_size = size;

out:
	return read_size;
}

static int rpmb_fs_write(TEE_Result *errno, int fd, const void *buf,
			size_t size)
{
	TEE_Result res;
	struct rpmb_file_handle *fh;
	tee_mm_pool_t p;
	bool pool_result = false;
	tee_mm_entry_t *mm;
	size_t end;
	size_t newsize;
	uint8_t *newbuf = NULL;
	uintptr_t newaddr;
	uint32_t start_addr;

	if (!size)
		return 0;

	if (!buf) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	if (!fs_par) {
		res = TEE_ERROR_GENERIC;
		goto out;
	}

	fh = handle_lookup(&fs_handle_db, fd);
	if (!fh) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}
	dump_fh(fh);

	/* Upper memory allocation must be used for RPMB_FS. */
	pool_result = tee_mm_init(&p,
				  RPMB_STORAGE_START_ADDRESS,
				  fs_par->max_rpmb_address,
				  RPMB_BLOCK_SIZE_SHIFT,
				  TEE_MM_POOL_HI_ALLOC);
	if (!pool_result) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	res = read_fat(fh, &p);
	if (res != TEE_SUCCESS)
		goto out;

	TEE_ASSERT(!(fh->fat_entry.flags & FILE_IS_LAST_ENTRY));

	end = fh->pos + size;
	start_addr = fh->fat_entry.start_address + fh->pos;

	if (end <= fh->fat_entry.data_size &&
	    tee_rpmb_write_is_atomic(CFG_RPMB_FS_DEV_ID, start_addr, size)) {

		DMSG("Updating data in-place");
		res = tee_rpmb_write(CFG_RPMB_FS_DEV_ID, start_addr, buf,
				     size, fh->fat_entry.fek);
		if (res != TEE_SUCCESS)
			goto out;
	} else {
		/*
		 * File must be extended, or update cannot be atomic: allocate,
		 * read, update, write.
		 */

		DMSG("Need to re-allocate");
		newsize = MAX(end, fh->fat_entry.data_size);
		mm = tee_mm_alloc(&p, newsize);
		newbuf = calloc(newsize, 1);
		if (!mm || !newbuf) {
			res = TEE_ERROR_OUT_OF_MEMORY;
			goto out;
		}

		if (fh->fat_entry.data_size) {
			res = tee_rpmb_read(CFG_RPMB_FS_DEV_ID,
					    fh->fat_entry.start_address,
					    newbuf, fh->fat_entry.data_size,
					    fh->fat_entry.fek);
			if (res != TEE_SUCCESS)
				goto out;
		}

		memcpy(newbuf + fh->pos, buf, size);

		newaddr = tee_mm_get_smem(mm);
		res = tee_rpmb_write(CFG_RPMB_FS_DEV_ID, newaddr, newbuf,
				     newsize, fh->fat_entry.fek);
		if (res != TEE_SUCCESS)
			goto out;

		fh->fat_entry.data_size = newsize;
		fh->fat_entry.start_address = newaddr;
		res = write_fat_entry(fh, true);
		if (res != TEE_SUCCESS)
			goto out;
	}

	fh->pos += size;
out:
	if (pool_result)
		tee_mm_final(&p);
	if (newbuf)
		free(newbuf);

	if (res == TEE_SUCCESS)
		return size;

	*errno = res;
	return -1;
}

static tee_fs_off_t rpmb_fs_lseek(TEE_Result *errno, int fd,
				  tee_fs_off_t offset, int whence)
{
	struct rpmb_file_handle *fh;
	TEE_Result res;
	tee_fs_off_t ret = -1;
	tee_fs_off_t new_pos;

	fh = handle_lookup(&fs_handle_db, fd);
	if (!fh)
		return TEE_ERROR_BAD_PARAMETERS;

	res = read_fat(fh, NULL);
	if (res != TEE_SUCCESS) {
		*errno = res;
		goto out;
	}

	switch (whence) {
	case TEE_FS_SEEK_SET:
		new_pos = offset;
		break;

	case TEE_FS_SEEK_CUR:
		new_pos = fh->pos + offset;
		break;

	case TEE_FS_SEEK_END:
		new_pos = fh->fat_entry.data_size + offset;
		break;

	default:
		*errno = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	if (new_pos < 0)
		new_pos = 0;

	if (new_pos > TEE_DATA_MAX_POSITION) {
		EMSG("Position is beyond TEE_DATA_MAX_POSITION");
		*errno = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	ret = fh->pos = new_pos;
out:
	return ret;
}

static int rpmb_fs_unlink(const char *filename)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct rpmb_file_handle *fh = NULL;

	if (!filename || strlen(filename) >= TEE_RPMB_FS_FILENAME_LENGTH - 1) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	fh = alloc_file_handle(filename);
	if (!fh) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	res = read_fat(fh, NULL);
	if (res != TEE_SUCCESS)
		goto out;

	/* Clear this file entry. */
	memset(&fh->fat_entry, 0, sizeof(struct rpmb_fat_entry));
	res = write_fat_entry(fh, false);

out:
	free(fh);
	return (res == TEE_SUCCESS ? 0 : -1);
}

static  int rpmb_fs_rename(const char *old_name, const char *new_name)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct rpmb_file_handle *fh_old = NULL;
	struct rpmb_file_handle *fh_new = NULL;
	uint32_t old_len;
	uint32_t new_len;

	if (!old_name || !new_name) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	old_len = strlen(old_name);
	new_len = strlen(new_name);

	if ((old_len >= TEE_RPMB_FS_FILENAME_LENGTH - 1) ||
	    (new_len >= TEE_RPMB_FS_FILENAME_LENGTH - 1) || (new_len == 0)) {

		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	fh_old = alloc_file_handle(old_name);
	if (!fh_old) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	fh_new = alloc_file_handle(new_name);
	if (!fh_new) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	res = read_fat(fh_old, NULL);
	if (res != TEE_SUCCESS)
		goto out;

	res = read_fat(fh_new, NULL);
	if (res == TEE_SUCCESS) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	memset(fh_old->fat_entry.filename, 0, TEE_RPMB_FS_FILENAME_LENGTH);
	memcpy(fh_old->fat_entry.filename, new_name, new_len);

	res = write_fat_entry(fh_old, false);

out:
	free(fh_old);
	free(fh_new);

	return (res == TEE_SUCCESS ? 0 : -1);
}

static int rpmb_fs_mkdir(const char *path __unused,
			 tee_fs_mode_t mode __unused)
{
	/*
	 * FIXME: mkdir() should really create some entry in the FAT so that
	 * access() would return success when the directory exists but is
	 * empty. This does not matter for the current use cases.
	 */
	return 0;
}

static int rpmb_fs_ftruncate(TEE_Result *errno, int fd, tee_fs_off_t length)
{
	struct rpmb_file_handle *fh;
	tee_mm_pool_t p;
	bool pool_result = false;
	tee_mm_entry_t *mm;
	uint32_t newsize;
	uint8_t *newbuf = NULL;
	uintptr_t newaddr;
	TEE_Result res = TEE_ERROR_GENERIC;

	if (length < 0 || length > INT32_MAX) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}
	newsize = length;

	fh = handle_lookup(&fs_handle_db, fd);
	if (!fh) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	res = read_fat(fh, NULL);
	if (res != TEE_SUCCESS)
		goto out;

	if (newsize > fh->fat_entry.data_size) {
		/* Extend file */

		pool_result = tee_mm_init(&p,
					  RPMB_STORAGE_START_ADDRESS,
					  fs_par->max_rpmb_address,
					  RPMB_BLOCK_SIZE_SHIFT,
					  TEE_MM_POOL_HI_ALLOC);
		if (!pool_result) {
			res = TEE_ERROR_OUT_OF_MEMORY;
			goto out;
		}
		res = read_fat(fh, &p);
		if (res != TEE_SUCCESS)
			goto out;

		mm = tee_mm_alloc(&p, newsize);
		newbuf = calloc(newsize, 1);
		if (!mm || !newbuf) {
			res = TEE_ERROR_OUT_OF_MEMORY;
			goto out;
		}

		if (fh->fat_entry.data_size) {
			res = tee_rpmb_read(CFG_RPMB_FS_DEV_ID,
					    fh->fat_entry.start_address,
					    newbuf, fh->fat_entry.data_size,
					    fh->fat_entry.fek);
			if (res != TEE_SUCCESS)
				goto out;
		}

		newaddr = tee_mm_get_smem(mm);
		res = tee_rpmb_write(CFG_RPMB_FS_DEV_ID, newaddr, newbuf,
				     newsize, fh->fat_entry.fek);
		if (res != TEE_SUCCESS)
			goto out;

	} else {
		/* Don't change file location */
		newaddr = fh->fat_entry.start_address;
	}

	/* fh->pos is unchanged */
	fh->fat_entry.data_size = newsize;
	fh->fat_entry.start_address = newaddr;
	res = write_fat_entry(fh, true);

out:
	if (pool_result)
		tee_mm_final(&p);
	if (newbuf)
		free(newbuf);

	if (res == TEE_SUCCESS)
		return 0;

	*errno = res;
	return -1;
}

static void rpmb_fs_dir_free(struct tee_fs_dir *dir)
{
	struct tee_rpmb_fs_dirent *e;

	if (!dir)
		return;

	free(dir->current);

	while ((e = SIMPLEQ_FIRST(&dir->next))) {
		SIMPLEQ_REMOVE_HEAD(&dir->next, link);
		free(e);
	}
}

static TEE_Result rpmb_fs_dir_populate(const char *path,
				       struct tee_fs_dir *dir)
{
	struct tee_rpmb_fs_dirent *current = NULL;
	struct rpmb_fat_entry *fat_entries = NULL;
	uint32_t fat_address;
	uint32_t filelen;
	char *filename;
	int i;
	bool last_entry_found = false;
	bool matched;
	struct tee_rpmb_fs_dirent *next = NULL;
	uint32_t pathlen;
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t size;
	char temp;

	res = rpmb_fs_setup();
	if (res != TEE_SUCCESS)
		goto out;

	res = get_fat_start_address(&fat_address);
	if (res != TEE_SUCCESS)
		goto out;

	size = N_ENTRIES * sizeof(struct rpmb_fat_entry);
	fat_entries = malloc(size);
	if (!fat_entries) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	pathlen = strlen(path);
	while (!last_entry_found) {
		res = tee_rpmb_read(CFG_RPMB_FS_DEV_ID, fat_address,
				    (uint8_t *)fat_entries, size, NULL);
		if (res != TEE_SUCCESS)
			goto out;

		for (i = 0; i < N_ENTRIES; i++) {
			filename = fat_entries[i].filename;
			if (fat_entries[i].flags & FILE_IS_ACTIVE) {
				matched = false;
				filelen = strlen(filename);
				if (filelen > pathlen) {
					temp = filename[pathlen];
					filename[pathlen] = '\0';
					if (strcmp(filename, path) == 0)
						matched = true;

					filename[pathlen] = temp;
				}

				if (matched) {
					next = malloc(sizeof(*next));
					if (!next) {
						res = TEE_ERROR_OUT_OF_MEMORY;
						goto out;
					}

					memset(next, 0, sizeof(*next));
					next->entry.d_name = next->name;
					memcpy(next->name,
						&filename[pathlen],
						filelen - pathlen);

					SIMPLEQ_INSERT_TAIL(&dir->next, next,
							    link);
					current = next;
				}
			}

			if (fat_entries[i].flags & FILE_IS_LAST_ENTRY) {
				last_entry_found = true;
				break;
			}

			/* Move to next fat_entry. */
			fat_address += sizeof(struct rpmb_fat_entry);
		}
	}

	/* No directories were found. */
	if (!current) {
		res = TEE_ERROR_NO_DATA;
		goto out;
	}

	res = TEE_SUCCESS;

out:
	if (res != TEE_SUCCESS)
		rpmb_fs_dir_free(dir);
	if (fat_entries)
		free(fat_entries);

	return res;
}

static TEE_Result rpmb_fs_opendir_internal(const char *path,
					   struct tee_fs_dir **dir)
{
	uint32_t len;
	uint32_t max_size;
	char path_local[TEE_RPMB_FS_FILENAME_LENGTH];
	TEE_Result res = TEE_ERROR_GENERIC;
	struct tee_fs_dir *rpmb_dir = NULL;

	if (!path || !dir) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	/*
	 * There must be room for at least the NULL char and a char for the
	 * filename after the path.
	 */
	max_size = TEE_RPMB_FS_FILENAME_LENGTH - 2;
	len = strlen(path);
	if (len > max_size || len == 0) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	memset(path_local, 0, sizeof(path_local));
	memcpy(path_local, path, len);

	/* Add a slash to correctly match the full directory name. */
	if (path_local[len - 1] != '/')
		path_local[len] = '/';

	rpmb_dir = calloc(1, sizeof(*rpmb_dir));
	if (!rpmb_dir) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}
	SIMPLEQ_INIT(&rpmb_dir->next);

	res = rpmb_fs_dir_populate(path_local, rpmb_dir);
	if (res != TEE_SUCCESS) {
		free(rpmb_dir);
		rpmb_dir = NULL;
		goto out;
	}

	*dir = rpmb_dir;

out:
	return res;
}

static struct tee_fs_dir *rpmb_fs_opendir(const char *path)
{
	struct tee_fs_dir *dir = NULL;
	TEE_Result res = TEE_ERROR_GENERIC;

	res = rpmb_fs_opendir_internal(path, &dir);
	if (res != TEE_SUCCESS)
		dir = NULL;

	return dir;
}


static struct tee_fs_dirent *rpmb_fs_readdir(struct tee_fs_dir *dir)
{
	if (!dir)
		return NULL;

	free(dir->current);

	dir->current = SIMPLEQ_FIRST(&dir->next);
	if (!dir->current)
		return NULL;

	SIMPLEQ_REMOVE_HEAD(&dir->next, link);

	return &dir->current->entry;
}

static int rpmb_fs_closedir(struct tee_fs_dir *dir)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	if (!dir) {
		res = TEE_SUCCESS;
		goto out;
	}

	rpmb_fs_dir_free(dir);
	free(dir);
	res = TEE_SUCCESS;
out:
	if (res == TEE_SUCCESS)
		return 0;

	return -1;
}

static int rpmb_fs_rmdir(const char *path)
{
	struct tee_fs_dir *dir = NULL;
	TEE_Result res = TEE_ERROR_GENERIC;
	int ret = -1;

	/* Open the directory anyting other than NO_DATA is a failure */
	res = rpmb_fs_opendir_internal(path, &dir);
	if (res == TEE_SUCCESS) {
		rpmb_fs_closedir(dir);
		ret = -1;

	} else if (res == TEE_ERROR_NO_DATA) {
		ret = 0;

	} else {
		/* The case any other failure is returned */
		ret = -1;
	}


	return ret;
}

static int rpmb_fs_stat(const char *filename, struct tee_rpmb_fs_stat *stat)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct rpmb_file_handle *fh = NULL;

	if (!stat || !filename) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	fh = alloc_file_handle(filename);
	if (!fh) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	res = read_fat(fh, NULL);
	if (res != TEE_SUCCESS)
		goto out;

	stat->size = (size_t)fh->fat_entry.data_size;
	stat->reserved = 0;

out:
	free(fh);
	return (res == TEE_SUCCESS ? 0 : -1);
}

static int rpmb_fs_access(const char *filename, int mode)
{
	struct tee_rpmb_fs_stat stat;
	TEE_Result res;

	/* Mode is currently ignored, this only checks for existence */
	(void)mode;

	res = rpmb_fs_stat(filename, &stat);

	if (res == TEE_SUCCESS)
		return 0;

	return -1;
}

static int rpmb_fs_open(TEE_Result *errno, const char *file, int flags, ...)
{
	int fd = -1;
	size_t len;

	assert(errno);
	*errno = TEE_SUCCESS;

	len = strlen(file) + 1;
	if (len > TEE_FS_NAME_MAX) {
		*errno = TEE_ERROR_BAD_PARAMETERS;
		goto exit;
	}

	/*
	 * try to open file without O_CREATE flag, if failed try again with
	 * O_CREATE flag (to distinguish whether it's a new file or not)
	 */
	fd = rpmb_fs_open_internal(file, flags & (~TEE_FS_O_CREATE));
	if (fd < 0) {
		if (!(flags & TEE_FS_O_CREATE)) {
			*errno = TEE_ERROR_ITEM_NOT_FOUND;
			goto exit;
		}

		fd = rpmb_fs_open_internal(file, flags);
		/* File has been created */
	} else {
		/* File already exists */
		if ((flags & TEE_FS_O_CREATE) && (flags & TEE_FS_O_EXCL)) {
			*errno = TEE_ERROR_ACCESS_CONFLICT;
			rpmb_fs_close(fd);
		}
	}

exit:
	return fd;
}

struct tee_file_operations tee_file_ops = {
	.open = rpmb_fs_open,
	.close = rpmb_fs_close,
	.read = rpmb_fs_read,
	.write = rpmb_fs_write,
	.lseek = rpmb_fs_lseek,
	.ftruncate = rpmb_fs_ftruncate,
	.rename = rpmb_fs_rename,
	.unlink = rpmb_fs_unlink,
	.mkdir = rpmb_fs_mkdir,
	.opendir = rpmb_fs_opendir,
	.closedir = rpmb_fs_closedir,
	.readdir = rpmb_fs_readdir,
	.rmdir = rpmb_fs_rmdir,
	.access = rpmb_fs_access
};
