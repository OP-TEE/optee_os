// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

#include <assert.h>
#include <config.h>
#include <crypto/crypto.h>
#include <kernel/huk_subkey.h>
#include <kernel/misc.h>
#include <kernel/msg_param.h>
#include <kernel/mutex.h>
#include <kernel/panic.h>
#include <kernel/tee_common.h>
#include <kernel/tee_common_otp.h>
#include <kernel/tee_misc.h>
#include <kernel/thread.h>
#include <kernel/user_access.h>
#include <mempool.h>
#include <mm/core_memprot.h>
#include <mm/mobj.h>
#include <mm/tee_mm.h>
#include <optee_rpc_cmd.h>
#include <stdlib.h>
#include <string_ext.h>
#include <string.h>
#include <sys/queue.h>
#include <tee/tee_fs.h>
#include <tee/tee_fs_key_manager.h>
#include <tee/tee_pobj.h>
#include <tee/tee_svc_storage.h>
#include <trace.h>
#include <util.h>

#define RPMB_STORAGE_START_ADDRESS      0
#define RPMB_FS_FAT_START_ADDRESS       512
#define RPMB_BLOCK_SIZE_SHIFT           8
#define RPMB_CID_PRV_OFFSET             9
#define RPMB_CID_CRC_OFFSET             15

#define RPMB_FS_MAGIC                   0x52504D42
#define FS_VERSION                      2

#define FILE_IS_ACTIVE                  (1u << 0)
#define FILE_IS_LAST_ENTRY              (1u << 1)

#define TEE_RPMB_FS_FILENAME_LENGTH 224

#define TMP_BLOCK_SIZE			4096U

#define RPMB_MAX_RETRIES		10

/**
 * Utilized when caching is enabled, i.e., when CFG_RPMB_FS_CACHE_ENTRIES > 0.
 * Cache size + the number of entries that are repeatedly read in and buffered
 * once the cache is full.
 */
#define RPMB_BUF_MAX_ENTRIES (CFG_RPMB_FS_CACHE_ENTRIES + \
			      CFG_RPMB_FS_RD_ENTRIES)

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
	uint32_t unused;
	uint8_t fek[TEE_FS_KM_FEK_SIZE];
	char filename[TEE_RPMB_FS_FILENAME_LENGTH];
};

/**
 * Structure that describes buffered/cached FAT FS entries in RPMB storage.
 * This structure is used in functions traversing the FAT FS.
 */
struct rpmb_fat_entry_dir {
	/*
	 * Buffer storing the FAT FS entries read in from RPMB storage. It
	 * includes the optional cache entries (CFG_RPMB_FS_CACHE_ENTRIES)
	 * and entries temporary read for current FAT FS traversal
	 * (CFG_RPMB_FS_RD_ENTRIES) when not found from cached entries.
	 */
	struct rpmb_fat_entry *rpmb_fat_entry_buf;
	/* Current index of FAT FS entry to read from buffer. */
	uint32_t idx_curr;
	/* Total number of FAT FS entries in buffer. */
	uint32_t num_buffered;
	/* Total number of FAT FS entries read during traversal. */
	uint32_t num_total_read;
	/* Indicates that last FAT FS entry was read. */
	bool last_reached;
};

/**
 * FAT entry context with reference to a FAT entry and its
 * location in RPMB.
 */
struct rpmb_file_handle {
	struct rpmb_fat_entry fat_entry;
	const TEE_UUID *uuid;
	char filename[TEE_RPMB_FS_FILENAME_LENGTH];
	/* Address for current entry in RPMB */
	uint32_t rpmb_fat_address;
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
 * A node in a list of directory entries.
 */
struct tee_rpmb_fs_dirent {
	struct tee_fs_dirent entry;
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
static struct rpmb_fat_entry_dir *fat_entry_dir;

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

/* If set to true, don't try to access RPMB until rebooted */
static bool rpmb_dead;

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

static TEE_Result tee_rpmb_key_gen(uint16_t dev_id __unused,
				   uint8_t *key, uint32_t len)
{
	uint8_t message[RPMB_EMMC_CID_SIZE];

	if (!key || RPMB_KEY_MAC_SIZE != len)
		return TEE_ERROR_BAD_PARAMETERS;

	IMSG("RPMB: Using generated key");

	/*
	 * PRV/CRC would be changed when doing eMMC FFU
	 * The following fields should be masked off when deriving RPMB key
	 *
	 * CID [55: 48]: PRV (Product revision)
	 * CID [07: 01]: CRC (CRC7 checksum)
	 * CID [00]: not used
	 */
	memcpy(message, rpmb_ctx->cid, RPMB_EMMC_CID_SIZE);
	memset(message + RPMB_CID_PRV_OFFSET, 0, 1);
	memset(message + RPMB_CID_CRC_OFFSET, 0, 1);
	return huk_subkey_derive(HUK_SUBKEY_RPMB, message, sizeof(message),
				 key, len);
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

static void get_op_result_bits(uint8_t *bytes, uint8_t *res)
{
	*res = *(bytes + 1) & RPMB_RESULT_MASK;
}

static TEE_Result tee_rpmb_mac_calc(uint8_t *mac, uint32_t macsize,
				    uint8_t *key, uint32_t keysize,
				    struct rpmb_data_frame *datafrms,
				    uint16_t blkcnt)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	int i;
	void *ctx = NULL;

	if (!mac || !key || !datafrms)
		return TEE_ERROR_BAD_PARAMETERS;

	res = crypto_mac_alloc_ctx(&ctx, TEE_ALG_HMAC_SHA256);
	if (res)
		return res;

	res = crypto_mac_init(ctx, key, keysize);
	if (res != TEE_SUCCESS)
		goto func_exit;

	for (i = 0; i < blkcnt; i++) {
		res = crypto_mac_update(ctx, datafrms[i].data,
					RPMB_MAC_PROTECT_DATA_SIZE);
		if (res != TEE_SUCCESS)
			goto func_exit;
	}

	res = crypto_mac_final(ctx, mac, macsize);
	if (res != TEE_SUCCESS)
		goto func_exit;

	res = TEE_SUCCESS;

func_exit:
	crypto_mac_free_ctx(ctx);
	return res;
}

struct tee_rpmb_mem {
	struct mobj *phreq_mobj;
	struct mobj *phresp_mobj;
	size_t req_size;
	size_t resp_size;
};

static void tee_rpmb_free(struct tee_rpmb_mem *mem)
{
	if (!mem)
		return;

	if (mem->phreq_mobj) {
		thread_rpc_free_payload(mem->phreq_mobj);
		mem->phreq_mobj = NULL;
	}
	if (mem->phresp_mobj) {
		thread_rpc_free_payload(mem->phresp_mobj);
		mem->phresp_mobj = NULL;
	}
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

	mem->phreq_mobj = thread_rpc_alloc_payload(req_s);
	mem->phresp_mobj = thread_rpc_alloc_payload(resp_s);

	if (!mem->phreq_mobj || !mem->phresp_mobj) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	*req = mobj_get_va(mem->phreq_mobj, 0, req_s);
	*resp = mobj_get_va(mem->phresp_mobj, 0, resp_s);
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
	struct thread_param params[2] = {
		[0] = THREAD_PARAM_MEMREF(IN, mem->phreq_mobj, 0,
					  mem->req_size),
		[1] = THREAD_PARAM_MEMREF(OUT, mem->phresp_mobj, 0,
					  mem->resp_size),
	};

	return thread_rpc_cmd(OPTEE_RPC_CMD_RPMB, 2, params);
}

static bool is_zero(const uint8_t *buf, size_t size)
{
	size_t i;

	for (i = 0; i < size; i++)
		if (buf[i])
			return false;
	return true;
}

static TEE_Result encrypt_block(uint8_t *out, const uint8_t *in,
				uint16_t blk_idx, const uint8_t *fek,
				const TEE_UUID *uuid)
{
	return tee_fs_crypt_block(uuid, out, in, RPMB_DATA_SIZE,
				  blk_idx, fek, TEE_MODE_ENCRYPT);
}

static TEE_Result decrypt_block(uint8_t *out, const uint8_t *in,
				uint16_t blk_idx, const uint8_t *fek,
				const TEE_UUID *uuid)
{
	return tee_fs_crypt_block(uuid, out, in, RPMB_DATA_SIZE,
				  blk_idx, fek, TEE_MODE_DECRYPT);
}

/* Decrypt/copy at most one block of data */
static TEE_Result decrypt(uint8_t *out, const struct rpmb_data_frame *frm,
			  size_t size, size_t offset,
			  uint16_t blk_idx __maybe_unused, const uint8_t *fek,
			  const TEE_UUID *uuid)
{
	uint8_t *tmp __maybe_unused;
	TEE_Result res = TEE_SUCCESS;


	if ((size + offset < size) || (size + offset > RPMB_DATA_SIZE))
		panic("invalid size or offset");

	if (!fek) {
		/* Block is not encrypted (not a file data block) */
		memcpy(out, frm->data + offset, size);
	} else if (is_zero(fek, TEE_FS_KM_FEK_SIZE)) {
		/* The file was created with encryption disabled */
		return TEE_ERROR_SECURITY;
	} else {
		/* Block is encrypted */
		if (size < RPMB_DATA_SIZE) {
			/*
			 * Since output buffer is not large enough to hold one
			 * block we must allocate a temporary buffer.
			 */
			tmp = malloc(RPMB_DATA_SIZE);
			if (!tmp)
				return TEE_ERROR_OUT_OF_MEMORY;
			res = decrypt_block(tmp, frm->data, blk_idx, fek, uuid);
			if (res == TEE_SUCCESS)
				memcpy(out, tmp + offset, size);
			free(tmp);
		} else {
			res = decrypt_block(out, frm->data, blk_idx, fek, uuid);
		}
	}

	return res;
}

static TEE_Result tee_rpmb_req_pack(struct rpmb_req *req,
				    struct rpmb_raw_data *rawdata,
				    uint16_t nbr_frms, uint16_t dev_id,
				    const uint8_t *fek, const TEE_UUID *uuid)
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
			if ((*rawdata->blk_idx + nbr_frms - 1) >
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
			if (fek) {
				res = encrypt_block(datafrm[i].data,
						    rawdata->data +
						    (i * RPMB_DATA_SIZE),
						    *rawdata->blk_idx + i,
						    fek, uuid);
				if (res != TEE_SUCCESS)
					goto func_exit;
			} else {
				memcpy(datafrm[i].data,
				       rawdata->data + (i * RPMB_DATA_SIZE),
				       RPMB_DATA_SIZE);
			}
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

	if (IS_ENABLED(CFG_RPMB_FS_DEBUG_DATA)) {
		for (i = 0; i < nbr_frms; i++) {
			DMSG("Dumping data frame %d:", i);
			DHEXDUMP((uint8_t *)&datafrm[i] + RPMB_STUFF_DATA_SIZE,
				 512 - RPMB_STUFF_DATA_SIZE);
		}
	}

	res = TEE_SUCCESS;
func_exit:
	free(datafrm);
	return res;
}

static TEE_Result data_cpy_mac_calc_1b(struct rpmb_raw_data *rawdata,
				       struct rpmb_data_frame *frm,
				       const uint8_t *fek, const TEE_UUID *uuid)
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

	res = decrypt(data, frm, rawdata->len, rawdata->byte_offset, idx, fek,
		      uuid);
	return res;
}

static TEE_Result tee_rpmb_data_cpy_mac_calc(struct rpmb_data_frame *datafrm,
					     struct rpmb_raw_data *rawdata,
					     uint16_t nbr_frms,
					     struct rpmb_data_frame *lastfrm,
					     const uint8_t *fek,
					     const TEE_UUID *uuid)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	int i;
	void *ctx = NULL;
	uint16_t offset;
	uint32_t size;
	uint8_t *data;
	uint16_t start_idx;
	struct rpmb_data_frame localfrm;

	if (!datafrm || !rawdata || !nbr_frms || !lastfrm)
		return TEE_ERROR_BAD_PARAMETERS;

	if (nbr_frms == 1)
		return data_cpy_mac_calc_1b(rawdata, lastfrm, fek, uuid);

	/* nbr_frms > 1 */

	data = rawdata->data;

	res = crypto_mac_alloc_ctx(&ctx, TEE_ALG_HMAC_SHA256);
	if (res)
		goto func_exit;

	res = crypto_mac_init(ctx, rpmb_ctx->key, RPMB_KEY_MAC_SIZE);
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

		res = crypto_mac_update(ctx, localfrm.data,
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
			      fek, uuid);
		if (res != TEE_SUCCESS)
			goto func_exit;

		data += size;
	}

	/* Last block */
	size = (rawdata->len + rawdata->byte_offset) % RPMB_DATA_SIZE;
	if (size == 0)
		size = RPMB_DATA_SIZE;
	res = decrypt(data, lastfrm, size, 0, start_idx + nbr_frms - 1, fek,
		      uuid);
	if (res != TEE_SUCCESS)
		goto func_exit;

	/* Update MAC against the last block */
	res = crypto_mac_update(ctx, lastfrm->data, RPMB_MAC_PROTECT_DATA_SIZE);
	if (res != TEE_SUCCESS)
		goto func_exit;

	res = crypto_mac_final(ctx, rawdata->key_mac, RPMB_KEY_MAC_SIZE);
	if (res != TEE_SUCCESS)
		goto func_exit;

	res = TEE_SUCCESS;

func_exit:
	crypto_mac_free_ctx(ctx);
	return res;
}

static TEE_Result tee_rpmb_resp_unpack_verify(struct rpmb_data_frame *datafrm,
					      struct rpmb_raw_data *rawdata,
					      uint16_t nbr_frms,
					      const uint8_t *fek,
					      const TEE_UUID *uuid)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint16_t msg_type;
	uint32_t wr_cnt;
	uint16_t blk_idx;
	uint8_t op_result;
	struct rpmb_data_frame lastfrm;

	if (!datafrm || !rawdata || !nbr_frms)
		return TEE_ERROR_BAD_PARAMETERS;

	if (IS_ENABLED(CFG_RPMB_FS_DEBUG_DATA)) {
		size_t i = 0;

		for (i = 0; i < nbr_frms; i++) {
			DMSG("Dumping data frame %zu:", i);
			DHEXDUMP((uint8_t *)&datafrm[i] + RPMB_STUFF_DATA_SIZE,
				 512 - RPMB_STUFF_DATA_SIZE);
		}
	}

	/* Make sure the last data packet can't be modified once verified */
	memcpy(&lastfrm, &datafrm[nbr_frms - 1], RPMB_DATA_FRAME_SIZE);

	/* Handle operation result and translate to TEEC error code. */
	get_op_result_bits(lastfrm.op_result, &op_result);
	if (op_result == RPMB_RESULT_AUTH_KEY_NOT_PROGRAMMED)
		return TEE_ERROR_ITEM_NOT_FOUND;
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
							 fek, uuid);

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

		if (consttime_memcmp(rawdata->key_mac,
				     (datafrm + nbr_frms - 1)->key_mac,
				     RPMB_KEY_MAC_SIZE) != 0) {
			DMSG("MAC mismatched:");
			if (IS_ENABLED(CFG_RPMB_FS_DEBUG_DATA))
				DHEXDUMP(rawdata->key_mac, RPMB_KEY_MAC_SIZE);

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

	if (IS_ENABLED(CFG_RPMB_FS_DEBUG_DATA)) {
		DMSG("Dumping dev_info:");
		DHEXDUMP((uint8_t *)dev_info, sizeof(struct rpmb_dev_info));
	}

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

	res = crypto_rng_read(nonce, RPMB_NONCE_SIZE);
	if (res != TEE_SUCCESS)
		goto func_exit;

	msg_type = RPMB_MSG_TYPE_REQ_WRITE_COUNTER_VAL_READ;

	memset(&rawdata, 0x00, sizeof(struct rpmb_raw_data));
	rawdata.msg_type = msg_type;
	rawdata.nonce = nonce;

	res = tee_rpmb_req_pack(req, &rawdata, 1, dev_id, NULL, NULL);
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

	res = tee_rpmb_resp_unpack_verify(resp, &rawdata, 1, NULL, NULL);
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
	} else
		EMSG("Verify key returning 0x%x", res);
	return res;
}

#ifdef CFG_RPMB_WRITE_KEY
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

	res = tee_rpmb_req_pack(req, &rawdata, 1, dev_id, NULL, NULL);
	if (res != TEE_SUCCESS)
		goto func_exit;

	res = tee_rpmb_invoke(&mem);
	if (res != TEE_SUCCESS)
		goto func_exit;

	msg_type = RPMB_MSG_TYPE_RESP_AUTH_KEY_PROGRAM;

	memset(&rawdata, 0x00, sizeof(struct rpmb_raw_data));
	rawdata.msg_type = msg_type;

	res = tee_rpmb_resp_unpack_verify(resp, &rawdata, 1, NULL, NULL);
	if (res != TEE_SUCCESS)
		goto func_exit;

	res = TEE_SUCCESS;

func_exit:
	tee_rpmb_free(&mem);
	return res;
}

static TEE_Result tee_rpmb_write_and_verify_key(uint16_t dev_id)
{
	TEE_Result res;

	if (!plat_rpmb_key_is_ready()) {
		DMSG("RPMB INIT: platform indicates RPMB key is not ready");
		return TEE_ERROR_BAD_STATE;
	}

	DMSG("RPMB INIT: Writing Key value:");
	DHEXDUMP(rpmb_ctx->key, RPMB_KEY_MAC_SIZE);

	res = tee_rpmb_write_key(dev_id);
	if (res == TEE_SUCCESS) {
		DMSG("RPMB INIT: Verifying Key");
		res = tee_rpmb_verify_key_sync_counter(dev_id);
	}
	return res;
}
#else
static TEE_Result tee_rpmb_write_and_verify_key(uint16_t dev_id __unused)
{
	DMSG("RPMB INIT: CFG_RPMB_WRITE_KEY is not set");
	return TEE_ERROR_STORAGE_NOT_AVAILABLE;
}
#endif

/* This function must never return TEE_SUCCESS if rpmb_ctx == NULL */
static TEE_Result tee_rpmb_init(uint16_t dev_id)
{
	TEE_Result res = TEE_SUCCESS;
	struct rpmb_dev_info dev_info = { };
	uint32_t nblocks = 0;

	if (rpmb_dead)
		return TEE_ERROR_COMMUNICATION;

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

		if (MUL_OVERFLOW(dev_info.rpmb_size_mult,
				 RPMB_SIZE_SINGLE / RPMB_DATA_SIZE, &nblocks) ||
		    SUB_OVERFLOW(nblocks, 1, &rpmb_ctx->max_blk_idx)) {
			res = TEE_ERROR_BAD_PARAMETERS;
			goto func_exit;
		}

		memcpy(rpmb_ctx->cid, dev_info.cid, RPMB_EMMC_CID_SIZE);

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
		if (res != TEE_SUCCESS) {
			EMSG("RPMB INIT: Deriving key failed with error 0x%x",
				res);
			goto func_exit;
		}

		rpmb_ctx->key_derived = true;
	}

	/* Perform a write counter read to verify if the key is ok. */
	if (!rpmb_ctx->wr_cnt_synced || !rpmb_ctx->key_verified) {
		DMSG("RPMB INIT: Verifying Key");

		res = tee_rpmb_verify_key_sync_counter(dev_id);
		if (res == TEE_ERROR_ITEM_NOT_FOUND &&
			!rpmb_ctx->key_verified) {
			/*
			 * Need to write the key here and verify it.
			 */
			DMSG("RPMB INIT: Auth key not yet written");
			res = tee_rpmb_write_and_verify_key(dev_id);
		} else if (res != TEE_SUCCESS) {
			EMSG("Verify key failed!");
			EMSG("Make sure key here matches device key");
		}
	}

func_exit:
	return res;
}

/*
 * Read RPMB data in bytes.
 *
 * @dev_id     Device ID of the eMMC device.
 * @addr       Byte address of data.
 * @data       Pointer to the data.
 * @len        Size of data in bytes.
 * @fek        Encrypted File Encryption Key or NULL.
 */
static TEE_Result tee_rpmb_read(uint16_t dev_id, uint32_t addr, uint8_t *data,
				uint32_t len, const uint8_t *fek,
				const TEE_UUID *uuid)
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

	if (len + byte_offset + RPMB_DATA_SIZE < RPMB_DATA_SIZE) {
		/* Overflow */
		return TEE_ERROR_BAD_PARAMETERS;
	}
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
	res = crypto_rng_read(nonce, RPMB_NONCE_SIZE);
	if (res != TEE_SUCCESS)
		goto func_exit;

	memset(&rawdata, 0x00, sizeof(struct rpmb_raw_data));
	rawdata.msg_type = msg_type;
	rawdata.nonce = nonce;
	rawdata.blk_idx = &blk_idx;
	res = tee_rpmb_req_pack(req, &rawdata, 1, dev_id, NULL, NULL);
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

	res = tee_rpmb_resp_unpack_verify(resp, &rawdata, blkcnt, fek, uuid);
	if (res != TEE_SUCCESS)
		goto func_exit;

	res = TEE_SUCCESS;

func_exit:
	tee_rpmb_free(&mem);
	return res;
}

static TEE_Result write_req(uint16_t dev_id, uint16_t blk_idx,
			    const void *data_blks, uint16_t blkcnt,
			    const uint8_t *fek, const TEE_UUID *uuid,
			    struct tee_rpmb_mem *mem, void  *req, void *resp)
{
	TEE_Result res = TEE_SUCCESS;
	uint8_t hmac[RPMB_KEY_MAC_SIZE] = { };
	uint32_t wr_cnt = rpmb_ctx->wr_cnt;
	struct rpmb_raw_data rawdata = { };
	size_t retry_count = 0;

	assert(mem->req_size <=
	       sizeof(struct rpmb_req) + blkcnt * RPMB_DATA_FRAME_SIZE);
	assert(mem->resp_size <= RPMB_DATA_FRAME_SIZE);

	while (true) {
		memset(req, 0, mem->req_size);
		memset(resp, 0, mem->resp_size);

		memset(&rawdata, 0, sizeof(struct rpmb_raw_data));
		rawdata.msg_type = RPMB_MSG_TYPE_REQ_AUTH_DATA_WRITE;
		rawdata.block_count = &blkcnt;
		rawdata.blk_idx = &blk_idx;
		rawdata.write_counter = &wr_cnt;
		rawdata.key_mac = hmac;
		rawdata.data = (uint8_t *)data_blks;

		res = tee_rpmb_req_pack(req, &rawdata, blkcnt, dev_id, fek,
					uuid);
		if (res) {
			/*
			 * If we haven't tried to send a request yet we can
			 * allow a failure here since there's no chance of
			 * an intercepted request with a valid write
			 * counter.
			 */
			if (!retry_count)
				return res;

			retry_count++;
			if (retry_count >= RPMB_MAX_RETRIES)
				goto out_of_retries;

			DMSG("Request pack failed, retrying %zu", retry_count);
			continue;
		}

		res = tee_rpmb_invoke(mem);
		if (res != TEE_SUCCESS) {
			retry_count++;
			if (retry_count >= RPMB_MAX_RETRIES)
				goto out_of_retries;
			/*
			 * To force wr_cnt sync next time, as it might get
			 * out of sync due to inconsistent operation result!
			 */
			rpmb_ctx->wr_cnt_synced = false;
			DMSG("Write invoke failed, retrying %zu", retry_count);
			continue;
		}

		memset(&rawdata, 0, sizeof(struct rpmb_raw_data));
		rawdata.msg_type = RPMB_MSG_TYPE_RESP_AUTH_DATA_WRITE;
		rawdata.block_count = &blkcnt;
		rawdata.blk_idx = &blk_idx;
		rawdata.write_counter = &wr_cnt;
		rawdata.key_mac = hmac;

		res = tee_rpmb_resp_unpack_verify(resp, &rawdata, 1, NULL,
						  NULL);
		if (res != TEE_SUCCESS) {
			retry_count++;
			if (retry_count >= RPMB_MAX_RETRIES)
				goto out_of_retries;
			/*
			 * To force wr_cnt sync next time, as it might get
			 * out of sync due to inconsistent operation result!
			 */
			rpmb_ctx->wr_cnt_synced = false;
			DMSG("Write resp unpack verify failed, retrying %zu",
			     retry_count);
			continue;
		}

		return TEE_SUCCESS;
	}

out_of_retries:
	rpmb_dead = true;
	/*
	 * We're using this error code to cause an eventuall calling TA to
	 * panic since we don't know if the data to be written has been
	 * committed to storage or not.
	 */
	return TEE_ERROR_COMMUNICATION;
}

static TEE_Result tee_rpmb_write_blk(uint16_t dev_id, uint16_t blk_idx,
				     const uint8_t *data_blks, uint16_t blkcnt,
				     const uint8_t *fek, const TEE_UUID *uuid)
{
	TEE_Result res;
	struct tee_rpmb_mem mem;
	struct rpmb_req *req = NULL;
	struct rpmb_data_frame *resp = NULL;
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
		size_t offs = i * rpmb_ctx->rel_wr_blkcnt * RPMB_DATA_SIZE;

		/*
		 * To handle the last write of block count which is
		 * equal or smaller than reliable write block count.
		 */
		if (i == nbr_writes - 1)
			tmp_blkcnt = blkcnt - rpmb_ctx->rel_wr_blkcnt *
			    (nbr_writes - 1);

		res = write_req(dev_id, tmp_blk_idx, data_blks + offs,
				tmp_blkcnt, fek, uuid, &mem, req, resp);
		if (res)
			goto out;


		tmp_blk_idx += tmp_blkcnt;
	}

out:
	tee_rpmb_free(&mem);
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
 * @fek        Encrypted File Encryption Key or NULL.
 */
static TEE_Result tee_rpmb_write(uint16_t dev_id, uint32_t addr,
				 const uint8_t *data, uint32_t len,
				 const uint8_t *fek, const TEE_UUID *uuid)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint8_t *data_tmp = NULL;
	uint16_t blk_idx;
	uint16_t blkcnt;
	uint8_t byte_offset;

	blk_idx = addr / RPMB_DATA_SIZE;
	byte_offset = addr % RPMB_DATA_SIZE;

	blkcnt =
	    ROUNDUP(len + byte_offset, RPMB_DATA_SIZE) / RPMB_DATA_SIZE;

	if (byte_offset == 0 && (len % RPMB_DATA_SIZE) == 0) {
		res = tee_rpmb_write_blk(dev_id, blk_idx, data, blkcnt, fek,
					 uuid);
		if (res != TEE_SUCCESS)
			goto func_exit;
	} else {
		data_tmp = calloc(blkcnt, RPMB_DATA_SIZE);
		if (!data_tmp) {
			res = TEE_ERROR_OUT_OF_MEMORY;
			goto func_exit;
		}

		/* Read the complete blocks */
		res = tee_rpmb_read(dev_id, blk_idx * RPMB_DATA_SIZE, data_tmp,
				    blkcnt * RPMB_DATA_SIZE, fek, uuid);
		if (res != TEE_SUCCESS)
			goto func_exit;

		/* Partial update of the data blocks */
		memcpy(data_tmp + byte_offset, data, len);

		res = tee_rpmb_write_blk(dev_id, blk_idx, data_tmp, blkcnt,
					 fek, uuid);
		if (res != TEE_SUCCESS)
			goto func_exit;
	}

	res = TEE_SUCCESS;

func_exit:
	free(data_tmp);
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

	if (rpmb_dead)
		return TEE_ERROR_COMMUNICATION;

	if (!rpmb_ctx || !rpmb_ctx->dev_info_synced) {
		res = tee_rpmb_init(dev_id);
		if (res != TEE_SUCCESS)
			goto func_exit;
	}

	*max_block = rpmb_ctx->max_blk_idx;

func_exit:
	return res;
}

/*
 * End of lower interface to RPMB device
 */

static TEE_Result get_fat_start_address(uint32_t *addr);
static TEE_Result rpmb_fs_setup(void);

/**
 * fat_entry_dir_free: Free the FAT entry dir.
 */
static void fat_entry_dir_free(void)
{
	if (fat_entry_dir) {
		free(fat_entry_dir->rpmb_fat_entry_buf);
		free(fat_entry_dir);
		fat_entry_dir = NULL;
	}
}

/**
 * fat_entry_dir_init: Initialize the FAT FS entry buffer/cache
 * This function must be called before reading FAT FS entries using the
 * function fat_entry_dir_get_next. This initializes the buffer/cache with the
 * first FAT FS entries.
 */
static TEE_Result fat_entry_dir_init(void)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct rpmb_fat_entry *fe = NULL;
	uint32_t fat_address = 0;
	uint32_t num_elems_read = 0;

	if (fat_entry_dir)
		return TEE_SUCCESS;

	res = rpmb_fs_setup();
	if (res)
		return res;

	res = get_fat_start_address(&fat_address);
	if (res)
		return res;

	fat_entry_dir = calloc(1, sizeof(struct rpmb_fat_entry_dir));
	if (!fat_entry_dir)
		return TEE_ERROR_OUT_OF_MEMORY;

	/*
	 * If caching is enabled, read in up to the maximum cache size, but
	 * never more than the single read in size. Otherwise, read in as many
	 * entries fit into the temporary buffer.
	 */
	if (CFG_RPMB_FS_CACHE_ENTRIES)
		num_elems_read = MIN(CFG_RPMB_FS_CACHE_ENTRIES,
				     CFG_RPMB_FS_RD_ENTRIES);
	else
		num_elems_read = CFG_RPMB_FS_RD_ENTRIES;

	/*
	 * Allocate memory for the FAT FS entries to read in.
	 */
	fe = calloc(num_elems_read, sizeof(struct rpmb_fat_entry));
	if (!fe) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	res = tee_rpmb_read(CFG_RPMB_FS_DEV_ID, fat_address, (uint8_t *)fe,
			    num_elems_read * sizeof(*fe), NULL, NULL);
	if (res)
		goto out;

	fat_entry_dir->rpmb_fat_entry_buf = fe;

	/*
	 * We use this variable when getting next entries from the buffer/cache
	 * to see whether we have to read in more entries from storage.
	 */
	fat_entry_dir->num_buffered = num_elems_read;

	return TEE_SUCCESS;
out:
	fat_entry_dir_free();
	free(fe);
	return res;
}

/**
 * fat_entry_dir_deinit: If caching is enabled, free the temporary buffer for
 * FAT FS entries in case the cache was too small. Keep the elements in the
 * cache. Reset the counter variables to start the next traversal from fresh
 * from the first cached entry. If caching is disabled, just free the
 * temporary buffer by calling fat_entry_dir_free and return.
 */
static void fat_entry_dir_deinit(void)
{
	struct rpmb_fat_entry *fe = NULL;

	if (!fat_entry_dir)
		return;

	if (!CFG_RPMB_FS_CACHE_ENTRIES) {
		fat_entry_dir_free();
		return;
	}

	fe = fat_entry_dir->rpmb_fat_entry_buf;
	fat_entry_dir->idx_curr = 0;
	fat_entry_dir->num_total_read = 0;
	fat_entry_dir->last_reached = false;

	if (fat_entry_dir->num_buffered > CFG_RPMB_FS_CACHE_ENTRIES) {
		fat_entry_dir->num_buffered = CFG_RPMB_FS_CACHE_ENTRIES;

		fe = realloc(fe, fat_entry_dir->num_buffered * sizeof(*fe));

		/*
		 * In case realloc fails, we are on the safe side if we destroy
		 * the whole structure. Upon the next init, the cache has to be
		 * re-established, but this case should not happen in practice.
		 */
		if (!fe)
			fat_entry_dir_free();
		else
			fat_entry_dir->rpmb_fat_entry_buf = fe;
	}
}

/**
 * fat_entry_dir_update: Updates a persisted FAT FS entry in the cache.
 * This function updates the FAT entry fat_entry that was written to address
 * fat_address onto RPMB storage in the cache.
 */
static TEE_Result __maybe_unused fat_entry_dir_update
					(struct rpmb_fat_entry *fat_entry,
					 uint32_t fat_address)
{
	uint32_t fat_entry_buf_idx = 0;
	/* Use a temp var to avoid compiler warning if caching disabled. */
	uint32_t max_cache_entries = CFG_RPMB_FS_CACHE_ENTRIES;

	assert(!((fat_address - RPMB_FS_FAT_START_ADDRESS) %
	       sizeof(struct rpmb_fat_entry)));

	/* Nothing to update if the cache is not initialized. */
	if (!fat_entry_dir)
		return TEE_SUCCESS;

	fat_entry_buf_idx = (fat_address - RPMB_FS_FAT_START_ADDRESS) /
			     sizeof(struct rpmb_fat_entry);

	/* Only need to write if index points to an entry in cache. */
	if (fat_entry_buf_idx < fat_entry_dir->num_buffered &&
	    fat_entry_buf_idx < max_cache_entries) {
		memcpy(fat_entry_dir->rpmb_fat_entry_buf + fat_entry_buf_idx,
		       fat_entry, sizeof(struct rpmb_fat_entry));
	}

	return TEE_SUCCESS;
}

/**
 * fat_entry_dir_get_next: Get next FAT FS entry.
 * Read either from cache/buffer, or by reading from RPMB storage if the
 * elements in the buffer/cache are fully read. When reading in from RPMB
 * storage, the buffer is overwritten in case caching is disabled.
 * In case caching is enabled, the cache is either further filled, or a
 * temporary buffer populated if the cache is already full.
 * The FAT FS entry is written to fat_entry. The respective address in RPMB
 * storage is written to fat_address, if not NULL. When the last FAT FS entry
 * was previously read, the function indicates this case by writing a NULL
 * pointer to fat_entry.
 * Returns a value different TEE_SUCCESS if the next FAT FS entry could not be
 * retrieved.
 */
static TEE_Result fat_entry_dir_get_next(struct rpmb_fat_entry **fat_entry,
					 uint32_t *fat_address)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct rpmb_fat_entry *fe = NULL;
	uint32_t num_elems_read = 0;
	uint32_t fat_address_local = 0;

	assert(fat_entry_dir && fat_entry);

	/* Don't read further if we previously read the last FAT FS entry. */
	if (fat_entry_dir->last_reached) {
		*fat_entry = NULL;
		return TEE_SUCCESS;
	}

	fe = fat_entry_dir->rpmb_fat_entry_buf;

	/* Determine address of FAT FS entry in RPMB storage. */
	fat_address_local = RPMB_FS_FAT_START_ADDRESS +
			(fat_entry_dir->num_total_read *
			sizeof(struct rpmb_fat_entry));

	/*
	 * We've read all so-far buffered elements, so we need to
	 * read in more entries from RPMB storage.
	 */
	if (fat_entry_dir->idx_curr >= fat_entry_dir->num_buffered) {
		/*
		 * This is the case where we do not cache entries, so just read
		 * in next set of FAT FS entries into the buffer.
		 * Goto the end of the when statement if that is done.
		 */
		if (!CFG_RPMB_FS_CACHE_ENTRIES) {
			num_elems_read = CFG_RPMB_FS_RD_ENTRIES;
			fat_entry_dir->idx_curr = 0;

			res = tee_rpmb_read(CFG_RPMB_FS_DEV_ID,
					    fat_address_local, (uint8_t *)fe,
					    num_elems_read * sizeof(*fe), NULL,
					    NULL);
			if (res)
				return res;
			goto post_read_in;
		}

		/*
		 * We cache FAT FS entries, and the buffer is not completely
		 * filled. Further keep on extending the buffer up to its max
		 * size by reading in from RPMB.
		 */
		if (fat_entry_dir->num_total_read < RPMB_BUF_MAX_ENTRIES) {
			/*
			 * Read at most as many elements as fit in the buffer
			 * and no more than the defined number of entries to
			 * read in at once.
			 */
			num_elems_read = MIN(RPMB_BUF_MAX_ENTRIES -
					     fat_entry_dir->num_total_read,
					     (uint32_t)CFG_RPMB_FS_RD_ENTRIES);

			/*
			 * Expand the buffer to fit in the additional entries.
			 */
			fe = realloc(fe,
				     (fat_entry_dir->num_buffered +
				      num_elems_read) * sizeof(*fe));
			if (!fe)
				return TEE_ERROR_OUT_OF_MEMORY;

			fat_entry_dir->rpmb_fat_entry_buf = fe;

			/* Read in to the next free slot in the buffer/cache. */
			res = tee_rpmb_read(CFG_RPMB_FS_DEV_ID,
					    fat_address_local,
					    (uint8_t *)(fe +
					    fat_entry_dir->num_total_read),
					    num_elems_read * sizeof(*fe),
					    NULL, NULL);
			if (res)
				return res;

			fat_entry_dir->num_buffered += num_elems_read;
		} else {
			/*
			 * This happens when we have read as many elements as
			 * can possibly fit into the buffer.
			 * As the first part of the buffer serves as our cache,
			 * we only overwrite the last part that serves as our
			 * temporary buffer used to iteratively read in entries
			 * when the cache is full. Read in the temporary buffer
			 * maximum size.
			 */
			num_elems_read = CFG_RPMB_FS_RD_ENTRIES;
			/* Reset index to beginning of the temporary buffer. */
			fat_entry_dir->idx_curr = CFG_RPMB_FS_CACHE_ENTRIES;

			/* Read in elements after the end of the cache. */
			res = tee_rpmb_read(CFG_RPMB_FS_DEV_ID,
					    fat_address_local,
					    (uint8_t *)(fe +
					    fat_entry_dir->idx_curr),
					    num_elems_read * sizeof(*fe),
					    NULL, NULL);
			if (res)
				return res;
		}
	}

post_read_in:
	if (fat_address)
		*fat_address = fat_address_local;

	*fat_entry = fe + fat_entry_dir->idx_curr;

	fat_entry_dir->idx_curr++;
	fat_entry_dir->num_total_read++;

	/*
	 * Indicate last entry was read.
	 * Ensures we return a zero value for fat_entry on next invocation.
	 */
	if ((*fat_entry)->flags & FILE_IS_LAST_ENTRY)
		fat_entry_dir->last_reached = true;

	return TEE_SUCCESS;
}

#if (TRACE_LEVEL >= TRACE_FLOW)
static void dump_fat(void)
{
	TEE_Result res = TEE_ERROR_SECURITY;
	struct rpmb_fat_entry *fe = NULL;

	if (!fs_par)
		return;

	if (fat_entry_dir_init())
		return;

	while (true) {
		res = fat_entry_dir_get_next(&fe, NULL);
		if (res || !fe)
			break;

		FMSG("flags %#"PRIx32", size %"PRIu32", address %#"PRIx32
		     ", filename '%s'",
		     fe->flags, fe->data_size, fe->start_address, fe->filename);
	}

	fat_entry_dir_deinit();
}
#else
static void dump_fat(void)
{
}
#endif

#if (TRACE_LEVEL >= TRACE_DEBUG)
static void dump_fh(struct rpmb_file_handle *fh)
{
	DMSG("fh->filename=%s", fh->filename);
	DMSG("fh->rpmb_fat_address=%u", fh->rpmb_fat_address);
	DMSG("fh->fat_entry.start_address=%u", fh->fat_entry.start_address);
	DMSG("fh->fat_entry.data_size=%u", fh->fat_entry.data_size);
}
#else
static void dump_fh(struct rpmb_file_handle *fh __unused)
{
}
#endif

/* "/TA_uuid/object_id" or "/TA_uuid/.object_id" */
static TEE_Result create_filename(void *buf, size_t blen, struct tee_pobj *po,
				  bool transient)
{
	uint8_t *file = buf;
	uint32_t pos = 0;
	uint32_t hslen = 1 /* Leading slash */
			+ TEE_B2HS_HSBUF_SIZE(sizeof(TEE_UUID) + po->obj_id_len)
			+ 1; /* Intermediate slash */

	/* +1 for the '.' (temporary persistent object) */
	if (transient)
		hslen++;

	if (blen < hslen)
		return TEE_ERROR_SHORT_BUFFER;

	file[pos++] = '/';
	pos += tee_b2hs((uint8_t *)&po->uuid, &file[pos],
			sizeof(TEE_UUID), hslen);
	file[pos++] = '/';

	if (transient)
		file[pos++] = '.';

	tee_b2hs(po->obj_id, file + pos, po->obj_id_len, hslen - pos);

	return TEE_SUCCESS;
}

/* "/TA_uuid" */
static TEE_Result create_dirname(void *buf, size_t blen, const TEE_UUID *uuid)
{
	uint8_t *dir = buf;
	uint32_t hslen = TEE_B2HS_HSBUF_SIZE(sizeof(TEE_UUID)) + 1;

	if (blen < hslen)
		return TEE_ERROR_SHORT_BUFFER;

	dir[0] = '/';
	tee_b2hs((uint8_t *)uuid, dir + 1, sizeof(TEE_UUID), hslen);

	return TEE_SUCCESS;
}

static struct rpmb_file_handle *alloc_file_handle(struct tee_pobj *po,
						  bool temporary)
{
	struct rpmb_file_handle *fh = NULL;

	fh = calloc(1, sizeof(struct rpmb_file_handle));
	if (!fh)
		return NULL;

	if (po)
		create_filename(fh->filename, sizeof(fh->filename), po,
				temporary);

	return fh;
}

/**
 * write_fat_entry: Store info in a fat_entry to RPMB.
 */
static TEE_Result write_fat_entry(struct rpmb_file_handle *fh)
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

	res = tee_rpmb_write(CFG_RPMB_FS_DEV_ID, fh->rpmb_fat_address,
			     (uint8_t *)&fh->fat_entry,
			     sizeof(struct rpmb_fat_entry), NULL, NULL);

	dump_fat();

	/* If caching enabled, update a successfully written entry in cache. */
	if (CFG_RPMB_FS_CACHE_ENTRIES && !res)
		res = fat_entry_dir_update(&fh->fat_entry,
					   fh->rpmb_fat_address);

out:
	return res;
}

/**
 * rpmb_fs_setup: Setup RPMB FS.
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

	/*
	 * We're going to read a full block in order to have a full block
	 * for the dummy write below.
	 */
	COMPILE_TIME_ASSERT(sizeof(struct rpmb_fs_partition) <=
			    RPMB_DATA_SIZE);
	partition_data = calloc(1, RPMB_DATA_SIZE);
	if (!partition_data) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	res = tee_rpmb_read(CFG_RPMB_FS_DEV_ID, RPMB_STORAGE_START_ADDRESS,
			    (uint8_t *)partition_data, RPMB_DATA_SIZE,
			    NULL, NULL);
	if (res != TEE_SUCCESS)
		goto out;
	/*
	 * Perform a write in order to increase the write counter. This
	 * prevents late usage (replay attack) of a previously blocked
	 * request with a valid write counter value.
	 */
	res = tee_rpmb_write(CFG_RPMB_FS_DEV_ID, RPMB_STORAGE_START_ADDRESS,
			     (uint8_t *)partition_data, RPMB_DATA_SIZE,
			     NULL, NULL);
	if (res != TEE_SUCCESS)
		goto out;
	/*
	 * We're reading again in case a stale request was committed
	 * instead of the one issued above. If this succeeds we're in sync
	 * with the RPMB block since there are no other possible stale
	 * blocks with valid write counters available.
	 */
	res = tee_rpmb_read(CFG_RPMB_FS_DEV_ID, RPMB_STORAGE_START_ADDRESS,
			    (uint8_t *)partition_data,
			    sizeof(struct rpmb_fs_partition), NULL, NULL);
	if (res != TEE_SUCCESS)
		goto out;

#ifndef CFG_RPMB_RESET_FAT
	if (partition_data->rpmb_fs_magic == RPMB_FS_MAGIC) {
		if (partition_data->fs_version == FS_VERSION) {
			res = TEE_SUCCESS;
			goto store_fs_par;
		} else {
			EMSG("Wrong software is in use.");
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
	fh = alloc_file_handle(NULL, false);
	if (!fh) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}
	fh->fat_entry.flags = FILE_IS_LAST_ENTRY;
	fh->rpmb_fat_address = partition_data->fat_start_address;

	/* Write init FAT entry and partition data to RPMB. */
	res = write_fat_entry(fh);
	if (res != TEE_SUCCESS)
		goto out;

	res = tee_rpmb_write(CFG_RPMB_FS_DEV_ID, RPMB_STORAGE_START_ADDRESS,
			     (uint8_t *)partition_data,
			     sizeof(struct rpmb_fs_partition), NULL, NULL);

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
	struct rpmb_fat_entry *fe = NULL;
	uint32_t fat_address;
	bool entry_found = false;
	bool expand_fat = false;
	struct rpmb_file_handle last_fh;

	DMSG("fat_address %d", fh->rpmb_fat_address);

	res = fat_entry_dir_init();
	if (res)
		goto out;

	/*
	 * The pool is used to represent the current RPMB layout. To find
	 * a slot for the file tee_mm_alloc is called on the pool. Thus
	 * if it is not NULL the entire FAT must be traversed to fill in
	 * the pool.
	 */
	while (true) {
		res = fat_entry_dir_get_next(&fe, &fat_address);
		if (res || !fe)
			break;

		/*
		 * Look for an entry, matching filenames. (read, rm,
		 * rename and stat.). Only store first filename match.
		 */
		if ((!strcmp(fh->filename, fe->filename)) &&
		    (fe->flags & FILE_IS_ACTIVE) && !entry_found) {
			entry_found = true;
			fh->rpmb_fat_address = fat_address;
			memcpy(&fh->fat_entry, fe, sizeof(*fe));
			if (!p)
				break;
		}

		/* Add existing files to memory pool. (write) */
		if (p) {
			if ((fe->flags & FILE_IS_ACTIVE) && fe->data_size > 0) {

				mm = tee_mm_alloc2(p, fe->start_address,
						   fe->data_size);
				if (!mm) {
					res = TEE_ERROR_OUT_OF_MEMORY;
					goto out;
				}
			}

			/* Unused FAT entries can be reused (write) */
			if (((fe->flags & FILE_IS_ACTIVE) == 0) &&
			    fh->rpmb_fat_address == 0) {
				fh->rpmb_fat_address = fat_address;
				memcpy(&fh->fat_entry, fe,
				       sizeof(struct rpmb_fat_entry));
			}

			if (((fe->flags & FILE_IS_LAST_ENTRY) != 0) &&
			    fh->rpmb_fat_address == fat_address) {

				/*
				 * If the last entry was reached and was chosen
				 * by the previous check, then the FAT needs to
				 * be expanded.
				 * fh->rpmb_fat_address is the address chosen
				 * to store the files FAT entry and fat_address
				 * is the current FAT entry address being
				 * compared.
				 */
				expand_fat = true;
			}
		}
	}

	if (res)
		goto out;
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
			res = write_fat_entry(&last_fh);
			if (res != TEE_SUCCESS)
				goto out;
		}
	}

	if (!fh->rpmb_fat_address)
		res = TEE_ERROR_ITEM_NOT_FOUND;

out:
	fat_entry_dir_deinit();
	return res;
}

static TEE_Result generate_fek(struct rpmb_fat_entry *fe, const TEE_UUID *uuid)
{
	TEE_Result res;

again:
	res = tee_fs_generate_fek(uuid, fe->fek, sizeof(fe->fek));
	if (res != TEE_SUCCESS)
		return res;

	if (is_zero(fe->fek, sizeof(fe->fek)))
		goto again;

	return res;
}

static TEE_Result rpmb_fs_open_internal(struct rpmb_file_handle *fh,
					const TEE_UUID *uuid, bool create)
{
	tee_mm_pool_t p;
	bool pool_result;
	paddr_size_t pool_sz = 0;
	TEE_Result res = TEE_ERROR_GENERIC;

	/* We need to do setup in order to make sure fs_par is filled in */
	res = rpmb_fs_setup();
	if (res != TEE_SUCCESS)
		goto out;

	fh->uuid = uuid;
	if (create) {
		/* Upper memory allocation must be used for RPMB_FS. */
		pool_sz = fs_par->max_rpmb_address - RPMB_STORAGE_START_ADDRESS;
		pool_result = tee_mm_init(&p,
					  RPMB_STORAGE_START_ADDRESS,
					  pool_sz,
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

	/*
	 * If this is opened with create and the entry found was not active
	 * then this is a new file and the FAT entry must be written
	 */
	if (create) {
		if ((fh->fat_entry.flags & FILE_IS_ACTIVE) == 0) {
			memset(&fh->fat_entry, 0,
				sizeof(struct rpmb_fat_entry));
			memcpy(fh->fat_entry.filename, fh->filename,
				strlen(fh->filename));
			/* Start address and size are 0 */
			fh->fat_entry.flags = FILE_IS_ACTIVE;

			res = generate_fek(&fh->fat_entry, uuid);
			if (res != TEE_SUCCESS)
				goto out;
			DMSG("GENERATE FEK key: %p",
			     (void *)fh->fat_entry.fek);
			DHEXDUMP(fh->fat_entry.fek, sizeof(fh->fat_entry.fek));

			res = write_fat_entry(fh);
			if (res != TEE_SUCCESS)
				goto out;
		}
	}

	res = TEE_SUCCESS;

out:
	return res;
}

static void rpmb_fs_close(struct tee_file_handle **tfh)
{
	struct rpmb_file_handle *fh = (struct rpmb_file_handle *)*tfh;

	free(fh);
	*tfh = NULL;
}

static TEE_Result rpmb_fs_read(struct tee_file_handle *tfh, size_t pos,
			       void *buf_core, void *buf_user, size_t *len)
{
	TEE_Result res;
	struct rpmb_file_handle *fh = (struct rpmb_file_handle *)tfh;
	size_t size = *len;

	/* One of buf_core and buf_user must be NULL */
	assert(!buf_core || !buf_user);

	if (!size)
		return TEE_SUCCESS;

	mutex_lock(&rpmb_mutex);

	dump_fh(fh);

	res = read_fat(fh, NULL);
	if (res != TEE_SUCCESS)
		goto out;

	if (pos >= fh->fat_entry.data_size) {
		*len = 0;
		goto out;
	}

	size = MIN(size, fh->fat_entry.data_size - pos);
	if (size) {
		if (buf_core) {
			res = tee_rpmb_read(CFG_RPMB_FS_DEV_ID,
					    fh->fat_entry.start_address + pos,
					    buf_core, size, fh->fat_entry.fek,
					    fh->uuid);
			if (res != TEE_SUCCESS)
				goto out;
		} else if (buf_user) {
			uint32_t f = TEE_MEMORY_ACCESS_WRITE;

			res = check_user_access(f, buf_user, size);
			if (res)
				goto out;
			enter_user_access();
			res = tee_rpmb_read(CFG_RPMB_FS_DEV_ID,
					    fh->fat_entry.start_address + pos,
					    buf_user, size, fh->fat_entry.fek,
					    fh->uuid);
			exit_user_access();
			if (res)
				goto out;
		}
	}
	*len = size;

out:
	mutex_unlock(&rpmb_mutex);
	return res;
}

static TEE_Result update_write_helper(struct rpmb_file_handle *fh,
				      size_t pos, const void *buf,
				      size_t size, uintptr_t new_fat,
				      size_t new_size)
{
	uintptr_t old_fat = fh->fat_entry.start_address;
	size_t old_size = fh->fat_entry.data_size;
	const uint8_t *rem_buf = buf;
	size_t rem_size = size;
	uint8_t *blk_buf = NULL;
	size_t blk_offset = 0;
	size_t blk_size = 0;
	TEE_Result res = TEE_SUCCESS;

	blk_buf = mempool_alloc(mempool_default, TMP_BLOCK_SIZE);
	if (!blk_buf)
		return TEE_ERROR_OUT_OF_MEMORY;

	while (blk_offset < new_size) {
		uint8_t *copy_dst = blk_buf;
		size_t copy_size = 0;
		size_t rd_size = 0;

		blk_size = MIN(TMP_BLOCK_SIZE, new_size - blk_offset);
		memset(blk_buf, 0, blk_size);

		/* Possibly read old RPMB data in temporary buffer */
		if (blk_offset < pos && blk_offset < old_size) {
			rd_size = MIN(blk_size, old_size - blk_offset);

			res = tee_rpmb_read(CFG_RPMB_FS_DEV_ID,
					    old_fat + blk_offset, blk_buf,
					    rd_size, fh->fat_entry.fek,
					    fh->uuid);
			if (res != TEE_SUCCESS)
				break;
		}

		/* Possibly update data in temporary buffer */
		if ((blk_offset + TMP_BLOCK_SIZE > pos) &&
		    (blk_offset < pos + size)) {
			size_t offset = 0;

			copy_dst = blk_buf;
			copy_size = TMP_BLOCK_SIZE;

			if (blk_offset < pos) {
				offset = pos - blk_offset;

				copy_dst += offset;
				copy_size -= offset;
			}
			copy_size = MIN(copy_size, rem_size);

			memcpy(copy_dst, rem_buf, copy_size);
			rem_buf += copy_size;
			rem_size -= copy_size;
		}

		/* Write temporary buffer to new RPMB destination */
		res = tee_rpmb_write(CFG_RPMB_FS_DEV_ID, new_fat + blk_offset,
				     blk_buf, blk_size,
				     fh->fat_entry.fek, fh->uuid);
		if (res != TEE_SUCCESS)
			break;

		blk_offset += blk_size;
	}

	mempool_free(mempool_default, blk_buf);

	return res;
}

static TEE_Result rpmb_fs_write_primitive(struct rpmb_file_handle *fh,
					  size_t pos, const void *buf,
					  size_t size)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	tee_mm_pool_t p = { };
	bool pool_result = false;
	size_t end = 0;
	uint32_t start_addr = 0;
	paddr_size_t pool_sz = 0;

	if (!size)
		return TEE_SUCCESS;

	if (!fs_par) {
		res = TEE_ERROR_GENERIC;
		goto out;
	}

	dump_fh(fh);

	/* Upper memory allocation must be used for RPMB_FS. */
	pool_sz = fs_par->max_rpmb_address - RPMB_STORAGE_START_ADDRESS;
	pool_result = tee_mm_init(&p,
				  RPMB_STORAGE_START_ADDRESS,
				  pool_sz,
				  RPMB_BLOCK_SIZE_SHIFT,
				  TEE_MM_POOL_HI_ALLOC);
	if (!pool_result) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	res = read_fat(fh, &p);
	if (res != TEE_SUCCESS)
		goto out;

	if (fh->fat_entry.flags & FILE_IS_LAST_ENTRY)
		panic("invalid last entry flag");

	if (ADD_OVERFLOW(pos, size, &end)) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}
	if (ADD_OVERFLOW(fh->fat_entry.start_address, pos, &start_addr)) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	if (end <= fh->fat_entry.data_size &&
	    tee_rpmb_write_is_atomic(CFG_RPMB_FS_DEV_ID, start_addr, size)) {

		DMSG("Updating data in-place");
		res = tee_rpmb_write(CFG_RPMB_FS_DEV_ID, start_addr, buf,
				     size, fh->fat_entry.fek, fh->uuid);
	} else {
		/*
		 * File must be extended, or update cannot be atomic: allocate,
		 * read, update, write.
		 */
		size_t new_size = MAX(end, fh->fat_entry.data_size);
		tee_mm_entry_t *mm = tee_mm_alloc(&p, new_size);
		uintptr_t new_fat_entry = 0;

		DMSG("Need to re-allocate");
		if (!mm) {
			DMSG("RPMB: No space left");
			res = TEE_ERROR_STORAGE_NO_SPACE;
			goto out;
		}

		new_fat_entry = tee_mm_get_smem(mm);

		res = update_write_helper(fh, pos, buf, size,
					  new_fat_entry, new_size);
		if (res == TEE_SUCCESS) {
			fh->fat_entry.data_size = new_size;
			fh->fat_entry.start_address = new_fat_entry;

			res = write_fat_entry(fh);
		}
	}

out:
	if (pool_result)
		tee_mm_final(&p);

	return res;
}

static TEE_Result rpmb_fs_write(struct tee_file_handle *tfh, size_t pos,
				const void *buf_core, const void *buf_user,
				size_t size)
{
	TEE_Result res = TEE_SUCCESS;

	/* One of buf_core and buf_user must be NULL */
	assert(!buf_core || !buf_user);

	if (!size)
		return TEE_SUCCESS;

	mutex_lock(&rpmb_mutex);
	if (buf_core) {
		res = rpmb_fs_write_primitive((struct rpmb_file_handle *)tfh,
					      pos, buf_core, size);
	} else if (buf_user) {
		uint32_t f = TEE_MEMORY_ACCESS_READ;

		res = check_user_access(f, buf_user, size);
		if (res)
			goto out;
		enter_user_access();
		res = rpmb_fs_write_primitive((struct rpmb_file_handle *)tfh,
					      pos, buf_user, size);
		exit_user_access();
	}
out:
	mutex_unlock(&rpmb_mutex);

	return res;
}

static TEE_Result rpmb_fs_remove_internal(struct rpmb_file_handle *fh)
{
	TEE_Result res;

	res = read_fat(fh, NULL);
	if (res)
		return res;

	/* Clear this file entry. */
	memset(&fh->fat_entry, 0, sizeof(struct rpmb_fat_entry));
	return write_fat_entry(fh);
}

static TEE_Result rpmb_fs_remove(struct tee_pobj *po)
{
	TEE_Result res;
	struct rpmb_file_handle *fh = alloc_file_handle(po, po->temporary);

	if (!fh)
		return TEE_ERROR_OUT_OF_MEMORY;

	mutex_lock(&rpmb_mutex);

	res = rpmb_fs_remove_internal(fh);

	mutex_unlock(&rpmb_mutex);

	free(fh);
	return res;
}

static  TEE_Result rpmb_fs_rename_internal(struct tee_pobj *old,
					   struct tee_pobj *new,
					   bool overwrite)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct rpmb_file_handle *fh_old = NULL;
	struct rpmb_file_handle *fh_new = NULL;

	if (!old) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	if (new)
		fh_old = alloc_file_handle(old, old->temporary);
	else
		fh_old = alloc_file_handle(old, true);
	if (!fh_old) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	if (new)
		fh_new = alloc_file_handle(new, new->temporary);
	else
		fh_new = alloc_file_handle(old, false);
	if (!fh_new) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	res = read_fat(fh_old, NULL);
	if (res != TEE_SUCCESS)
		goto out;

	res = read_fat(fh_new, NULL);
	if (res == TEE_SUCCESS) {
		if (!overwrite) {
			res = TEE_ERROR_ACCESS_CONFLICT;
			goto out;
		}

		/* Clear this file entry. */
		memset(&fh_new->fat_entry, 0, sizeof(struct rpmb_fat_entry));
		res = write_fat_entry(fh_new);
		if (res != TEE_SUCCESS)
			goto out;
	}

	memset(fh_old->fat_entry.filename, 0, TEE_RPMB_FS_FILENAME_LENGTH);
	memcpy(fh_old->fat_entry.filename, fh_new->filename,
	       strlen(fh_new->filename));

	res = write_fat_entry(fh_old);

out:
	free(fh_old);
	free(fh_new);

	return res;
}

static  TEE_Result rpmb_fs_rename(struct tee_pobj *old, struct tee_pobj *new,
				  bool overwrite)
{
	TEE_Result res;

	mutex_lock(&rpmb_mutex);
	res = rpmb_fs_rename_internal(old, new, overwrite);
	mutex_unlock(&rpmb_mutex);

	return res;
}

static TEE_Result rpmb_fs_truncate(struct tee_file_handle *tfh, size_t length)
{
	struct rpmb_file_handle *fh = (struct rpmb_file_handle *)tfh;
	tee_mm_pool_t p;
	bool pool_result = false;
	tee_mm_entry_t *mm;
	uint32_t newsize;
	uint8_t *newbuf = NULL;
	uintptr_t newaddr;
	TEE_Result res = TEE_ERROR_GENERIC;
	paddr_size_t pool_sz = 0;

	mutex_lock(&rpmb_mutex);

	if (length > INT32_MAX) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}
	newsize = length;

	res = read_fat(fh, NULL);
	if (res != TEE_SUCCESS)
		goto out;

	if (newsize > fh->fat_entry.data_size) {
		/* Extend file */

		pool_sz = fs_par->max_rpmb_address - RPMB_STORAGE_START_ADDRESS;
		pool_result = tee_mm_init(&p,
					  RPMB_STORAGE_START_ADDRESS,
					  pool_sz,
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
		newbuf = calloc(1, newsize);
		if (!mm || !newbuf) {
			res = TEE_ERROR_OUT_OF_MEMORY;
			goto out;
		}

		if (fh->fat_entry.data_size) {
			res = tee_rpmb_read(CFG_RPMB_FS_DEV_ID,
					    fh->fat_entry.start_address,
					    newbuf, fh->fat_entry.data_size,
					    fh->fat_entry.fek, fh->uuid);
			if (res != TEE_SUCCESS)
				goto out;
		}

		newaddr = tee_mm_get_smem(mm);
		res = tee_rpmb_write(CFG_RPMB_FS_DEV_ID, newaddr, newbuf,
				     newsize, fh->fat_entry.fek, fh->uuid);
		if (res != TEE_SUCCESS)
			goto out;

	} else {
		/* Don't change file location */
		newaddr = fh->fat_entry.start_address;
	}

	/* fh->pos is unchanged */
	fh->fat_entry.data_size = newsize;
	fh->fat_entry.start_address = newaddr;
	res = write_fat_entry(fh);

out:
	mutex_unlock(&rpmb_mutex);
	if (pool_result)
		tee_mm_final(&p);
	if (newbuf)
		free(newbuf);

	return res;
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
	struct rpmb_fat_entry *fe = NULL;
	uint32_t fat_address;
	uint32_t filelen;
	char *filename;
	bool matched;
	struct tee_rpmb_fs_dirent *next = NULL;
	uint32_t pathlen;
	TEE_Result res = TEE_ERROR_GENERIC;
	char temp;

	mutex_lock(&rpmb_mutex);

	res = fat_entry_dir_init();
	if (res)
		goto out;

	pathlen = strlen(path);

	while (true) {
		res = fat_entry_dir_get_next(&fe, &fat_address);
		if (res || !fe)
			break;

		filename = fe->filename;
		if (fe->flags & FILE_IS_ACTIVE) {
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

				next->entry.oidlen = tee_hs2b((uint8_t *)
						&filename[pathlen],
						next->entry.oid,
						filelen - pathlen,
						sizeof(next->entry.oid));
				if (next->entry.oidlen) {
					SIMPLEQ_INSERT_TAIL(&dir->next,
							    next, link);
					current = next;
				} else {
					free(next);
					next = NULL;
				}
			}
		}
	}

	if (res)
		goto out;

	if (current)
		res = TEE_SUCCESS;
	else
		res = TEE_ERROR_ITEM_NOT_FOUND; /* No directories were found. */

out:
	mutex_unlock(&rpmb_mutex);
	fat_entry_dir_deinit();
	if (res)
		rpmb_fs_dir_free(dir);

	return res;
}

static TEE_Result rpmb_fs_opendir(const TEE_UUID *uuid, struct tee_fs_dir **dir)
{
	uint32_t len;
	char path_local[TEE_RPMB_FS_FILENAME_LENGTH];
	TEE_Result res = TEE_ERROR_GENERIC;
	struct tee_fs_dir *rpmb_dir = NULL;

	if (!uuid || !dir) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	memset(path_local, 0, sizeof(path_local));
	if (create_dirname(path_local, sizeof(path_local) - 1, uuid)) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}
	len = strlen(path_local);

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

static TEE_Result rpmb_fs_readdir(struct tee_fs_dir *dir,
				  struct tee_fs_dirent **ent)
{
	if (!dir)
		return TEE_ERROR_GENERIC;

	free(dir->current);

	dir->current = SIMPLEQ_FIRST(&dir->next);
	if (!dir->current)
		return TEE_ERROR_ITEM_NOT_FOUND;

	SIMPLEQ_REMOVE_HEAD(&dir->next, link);

	*ent = &dir->current->entry;
	return TEE_SUCCESS;
}

static void rpmb_fs_closedir(struct tee_fs_dir *dir)
{
	if (dir) {
		rpmb_fs_dir_free(dir);
		free(dir);
	}
}

static TEE_Result rpmb_fs_open(struct tee_pobj *po, size_t *size,
			       struct tee_file_handle **ret_fh)
{
	TEE_Result res;
	struct rpmb_file_handle *fh = alloc_file_handle(po, po->temporary);

	if (!fh)
		return TEE_ERROR_OUT_OF_MEMORY;

	mutex_lock(&rpmb_mutex);

	res = rpmb_fs_open_internal(fh, &po->uuid, false);
	if (!res && size)
		*size = fh->fat_entry.data_size;

	mutex_unlock(&rpmb_mutex);

	if (res)
		free(fh);
	else
		*ret_fh = (struct tee_file_handle *)fh;

	return res;
}

static TEE_Result rpmb_fs_create(struct tee_pobj *po, bool overwrite,
				 const void *head, size_t head_size,
				 const void *attr, size_t attr_size,
				 const void *data_core, const void *data_user,
				 size_t data_size,
				 struct tee_file_handle **ret_fh)
{
	TEE_Result res;
	size_t pos = 0;
	struct rpmb_file_handle *fh = alloc_file_handle(po, po->temporary);

	/* One of data_core and data_user must be NULL */
	assert(!data_core || !data_user);

	if (!fh)
		return TEE_ERROR_OUT_OF_MEMORY;

	mutex_lock(&rpmb_mutex);
	res = rpmb_fs_open_internal(fh, &po->uuid, true);
	if (res)
		goto out;

	if (head && head_size) {
		res = rpmb_fs_write_primitive(fh, pos, head, head_size);
		if (res)
			goto out;
		pos += head_size;
	}

	if (attr && attr_size) {
		res = rpmb_fs_write_primitive(fh, pos, attr, attr_size);
		if (res)
			goto out;
		pos += attr_size;
	}

	if (data_size) {
		if (data_core) {
			res = rpmb_fs_write_primitive(fh, pos, data_core,
						      data_size);
			if (res)
				goto out;
		} else if (data_user) {
			uint32_t f = TEE_MEMORY_ACCESS_READ |
				     TEE_MEMORY_ACCESS_ANY_OWNER;

			res = check_user_access(f, data_user, data_size);
			if (res)
				goto out;
			enter_user_access();
			res = rpmb_fs_write_primitive(fh, pos, data_user,
						      data_size);
			exit_user_access();
			if (res)
				goto out;
		}
	}

	if (po->temporary) {
		/*
		 * If it's a temporary filename (which it normally is)
		 * rename into the final filename now that the file is
		 * fully initialized.
		 */
		po->temporary = false;
		res = rpmb_fs_rename_internal(po, NULL, overwrite);
		if (res) {
			po->temporary = true;
			goto out;
		}
		/* Update file handle after rename. */
		create_filename(fh->filename, sizeof(fh->filename), po, false);
	}

out:
	if (res) {
		rpmb_fs_remove_internal(fh);
		free(fh);
	} else {
		*ret_fh = (struct tee_file_handle *)fh;
	}
	mutex_unlock(&rpmb_mutex);

	return res;
}

const struct tee_file_operations rpmb_fs_ops = {
	.open = rpmb_fs_open,
	.create = rpmb_fs_create,
	.close = rpmb_fs_close,
	.read = rpmb_fs_read,
	.write = rpmb_fs_write,
	.truncate = rpmb_fs_truncate,
	.rename = rpmb_fs_rename,
	.remove = rpmb_fs_remove,
	.opendir = rpmb_fs_opendir,
	.closedir = rpmb_fs_closedir,
	.readdir = rpmb_fs_readdir,
};

TEE_Result tee_rpmb_fs_raw_open(const char *fname, bool create,
				struct tee_file_handle **ret_fh)
{
	TEE_Result res;
	struct rpmb_file_handle *fh = calloc(1, sizeof(*fh));
	static const TEE_UUID uuid = { 0 };

	if (!fh)
		return TEE_ERROR_OUT_OF_MEMORY;

	snprintf(fh->filename, sizeof(fh->filename), "/%s", fname);

	mutex_lock(&rpmb_mutex);

	res = rpmb_fs_open_internal(fh, &uuid, create);

	mutex_unlock(&rpmb_mutex);

	if (res) {
		if (create)
			rpmb_fs_remove_internal(fh);
		free(fh);
	} else {
		*ret_fh = (struct tee_file_handle *)fh;
	}

	return res;
}

bool __weak plat_rpmb_key_is_ready(void)
{
	return true;
}
