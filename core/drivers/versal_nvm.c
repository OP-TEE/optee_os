// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2022 Foundries.io Ltd
 * Jorge Ramirez-Ortiz <jorge@foundries.io>
 */

#include <arm.h>
#include <drivers/versal_nvm.h>
#include <drivers/versal_mbox.h>
#include <initcall.h>
#include <kernel/panic.h>
#include <kernel/tee_misc.h>
#include <mm/core_memprot.h>
#include <string.h>
#include <tee/cache.h>

#include "drivers/versal_nvm.h"

#define NVM_WORD_LEN 4

/* Protocol API with the remote processor */
#define NVM_MODULE_SHIFT		8
#define NVM_MODULE			11
#define NVM_API_ID(_id) ((NVM_MODULE << NVM_MODULE_SHIFT) | (_id))

#define __aligned_efuse			__aligned(CACHELINE_LEN)

/* Internal */
struct versal_efuse_puf_fuse_addr {
	uint64_t data_addr;
	uint32_t start_row;
	uint32_t num_rows;
	uint8_t env_monitor_dis;
	uint8_t prgm_puf_fuse;
	uint8_t pad[46];
};

/*
 * Max size of the buffer needed for the remote processor to DMA efuse _data_
 * to/from
 */
#define EFUSE_MAX_LEN (EFUSE_MAX_USER_FUSES * sizeof(uint32_t))

enum versal_nvm_api_id {
	API_FEATURES				= 0,
	BBRAM_WRITE_AES_KEY			= 1,
	BBRAM_ZEROIZE				= 2,
	BBRAM_WRITE_USER_DATA			= 3,
	BBRAM_READ_USER_DATA			= 4,
	BBRAM_LOCK_WRITE_USER_DATA		= 5,
	EFUSE_WRITE				= 6,
	EFUSE_WRITE_PUF				= 7,
	EFUSE_PUF_USER_FUSE_WRITE		= 8,
	EFUSE_READ_IV				= 9,
	EFUSE_READ_REVOCATION_ID		= 10,
	EFUSE_READ_OFFCHIP_REVOCATION_ID	= 11,
	EFUSE_READ_USER_FUSES			= 12,
	EFUSE_READ_MISC_CTRL			= 13,
	EFUSE_READ_SEC_CTRL			= 14,
	EFUSE_READ_SEC_MISC1			= 15,
	EFUSE_READ_BOOT_ENV_CTRL		= 16,
	EFUSE_READ_PUF_SEC_CTRL			= 17,
	EFUSE_READ_PPK_HASH			= 18,
	EFUSE_READ_DEC_EFUSE_ONLY		= 19,
	EFUSE_READ_DNA				= 20,
	EFUSE_READ_PUF_USER_FUSES		= 21,
	EFUSE_READ_PUF				= 22,
	EFUSE_INVALID				= 23,
};

/* uint64_t are memory addresses */
struct versal_efuse_data {
	uint64_t env_mon_dis_flag;
	uint64_t aes_key_addr;
	uint64_t ppk_hash_addr;
	uint64_t dec_only_addr;
	uint64_t sec_ctrl_addr;
	uint64_t misc_ctrl_addr;
	uint64_t revoke_id_addr;
	uint64_t iv_addr;
	uint64_t user_fuse_addr;
	uint64_t glitch_cfg_addr;
	uint64_t boot_env_ctrl_addr;
	uint64_t misc1_ctrl_addr;
	uint64_t offchip_id_addr;
	uint8_t pad[24];
};

/* Helper read and write requests (not part of the protocol) */
struct versal_nvm_buf {
	size_t len;
	void *buf;
};

struct versal_nvm_read_req {
	enum versal_nvm_api_id efuse_id;
	enum versal_nvm_revocation_id revocation_id;
	enum versal_nvm_offchip_id offchip_id;
	enum versal_nvm_ppk_type ppk_type;
	enum versal_nvm_iv_type iv_type;
	struct versal_nvm_buf ibuf[VERSAL_MAX_IPI_BUF];
};

struct versal_bbram_data {
	size_t aes_key_len;
	uint32_t user_data;
};

struct versal_nvm_write_req {
	struct versal_efuse_data data;
	struct versal_bbram_data bbram;
	struct versal_nvm_buf ibuf[VERSAL_MAX_IPI_BUF];
	enum versal_nvm_api_id efuse_id;
};

static TEE_Result
prepare_cmd(struct versal_ipi_cmd *cmd, enum versal_nvm_api_id efuse,
	    struct versal_nvm_buf *ibufs, uint32_t *arg)
{
	uint32_t a = 0;
	uint32_t b = 0;
	size_t i = 0;

	cmd->data[i++] = NVM_API_ID(efuse);
	if (arg)
		cmd->data[i++] = *arg;

	if (!ibufs[0].buf)
		return TEE_SUCCESS;

	reg_pair_from_64(virt_to_phys(ibufs[0].buf), &b, &a);

	cmd->data[i++] = a;
	cmd->data[i++] = b;

	for (i = 0; i < VERSAL_MAX_IPI_BUF; i++) {
		cmd->ibuf[i].mem.alloc_len = ibufs[i].len;
		cmd->ibuf[i].mem.buf = ibufs[i].buf;
	}

	return TEE_SUCCESS;
}

static TEE_Result efuse_req(enum versal_nvm_api_id efuse,
			    struct versal_nvm_buf *ibufs, uint32_t *arg)
{
	struct versal_ipi_cmd cmd = { };
	TEE_Result ret = TEE_SUCCESS;

	ret = prepare_cmd(&cmd, efuse, ibufs, arg);
	if (ret)
		return ret;

	ret = versal_mbox_notify(&cmd, NULL, NULL);
	if (ret)
		EMSG("Mailbox error");

	return ret;
}

static TEE_Result versal_alloc_read_buffer(struct versal_nvm_read_req *req)
{
	assert(req);
	req->ibuf[0].len = 1024;
	req->ibuf[0].buf = alloc_cache_aligned(req->ibuf[0].len);
	if (!req->ibuf[0].buf)
		return TEE_ERROR_OUT_OF_MEMORY;

	return TEE_SUCCESS;
}

static void versal_free_read_buffer(struct versal_nvm_read_req *req)
{
	assert(req);
	free(req->ibuf[0].buf);
}

static void *versal_get_read_buffer(struct versal_nvm_read_req *req)
{
	assert(req);
	return req->ibuf[0].buf;
}

static TEE_Result versal_nvm_read(struct versal_nvm_read_req *req)
{
	uint32_t *arg = NULL;
	uint32_t val = 0;

	if (!req)
		return TEE_ERROR_GENERIC;

	switch (req->efuse_id) {
	case EFUSE_READ_DNA:
	case EFUSE_READ_DEC_EFUSE_ONLY:
	case EFUSE_READ_PUF_SEC_CTRL:
	case EFUSE_READ_BOOT_ENV_CTRL:
	case EFUSE_READ_SEC_CTRL:
	case EFUSE_READ_MISC_CTRL:
	case EFUSE_READ_SEC_MISC1:
	case EFUSE_READ_USER_FUSES:
	case EFUSE_READ_PUF_USER_FUSES:
	case EFUSE_READ_PUF:
		break;
	case EFUSE_READ_OFFCHIP_REVOCATION_ID:
		val = req->offchip_id;
		arg = &val;
		break;
	case EFUSE_READ_REVOCATION_ID:
		val = req->revocation_id;
		arg = &val;
		break;
	case EFUSE_READ_IV:
		val = req->iv_type;
		arg = &val;
		break;
	case EFUSE_READ_PPK_HASH:
		val = req->ppk_type;
		arg = &val;
		break;
	case BBRAM_READ_USER_DATA:
		break;
	default:
		return TEE_ERROR_GENERIC;
	}

	return efuse_req(req->efuse_id, req->ibuf, arg);
}

static TEE_Result versal_nvm_write(struct versal_nvm_write_req *req)
{
	uint32_t *arg = NULL;
	uint32_t val = 0;

	switch (req->efuse_id) {
	case BBRAM_WRITE_AES_KEY:
		val = req->bbram.aes_key_len;
		arg = &val;
		break;
	case BBRAM_WRITE_USER_DATA:
		val = req->bbram.user_data;
		arg = &val;
		break;
	case EFUSE_PUF_USER_FUSE_WRITE:
	case EFUSE_WRITE_PUF:
	case EFUSE_WRITE:
		break;
	default:
		return TEE_ERROR_GENERIC;
	}

	return efuse_req(req->efuse_id, req->ibuf, arg);
}

TEE_Result versal_efuse_read_user_data(uint32_t *buf, size_t len,
				       uint32_t first, size_t num)
{
	struct versal_efuse_user_data cfg __aligned_efuse = {
		.start = first,
		.num = num,
	};
	struct versal_nvm_read_req req = {
		.efuse_id = EFUSE_READ_USER_FUSES,
	};
	void *rsp = NULL;

	if (first + num > EFUSE_MAX_USER_FUSES || len < num * sizeof(uint32_t))
		return TEE_ERROR_BAD_PARAMETERS;

	rsp = alloc_cache_aligned(1024);
	if (!rsp)
		return TEE_ERROR_OUT_OF_MEMORY;

	req.ibuf[0].buf = &cfg;
	req.ibuf[0].len = sizeof(cfg);
	req.ibuf[1].buf = rsp;
	req.ibuf[1].len = 1024;

	cfg.addr = virt_to_phys((void *)rsp);

	if (versal_nvm_read(&req)) {
		free(rsp);
		return TEE_ERROR_GENERIC;
	}

	memcpy(buf, rsp, num * sizeof(uint32_t));
	free(rsp);

	return TEE_SUCCESS;
}

TEE_Result versal_efuse_read_dna(uint32_t *buf, size_t len)
{
	struct versal_nvm_read_req req = {
		.efuse_id = EFUSE_READ_DNA,
	};

	if (len < EFUSE_DNA_LEN)
		return TEE_ERROR_BAD_PARAMETERS;

	if (versal_alloc_read_buffer(&req))
		return TEE_ERROR_OUT_OF_MEMORY;

	if (versal_nvm_read(&req)) {
		versal_free_read_buffer(&req);
		return TEE_ERROR_GENERIC;
	}

	memcpy(buf, versal_get_read_buffer(&req), EFUSE_DNA_LEN);
	versal_free_read_buffer(&req);

	return TEE_SUCCESS;
}

TEE_Result versal_efuse_read_iv(uint32_t *buf, size_t len,
				enum versal_nvm_iv_type type)
{
	struct versal_nvm_read_req req = {
		.efuse_id = EFUSE_READ_IV,
		.iv_type = type,
	};

	if (len < EFUSE_IV_LEN)
		return TEE_ERROR_BAD_PARAMETERS;

	if (versal_alloc_read_buffer(&req))
		return TEE_ERROR_OUT_OF_MEMORY;

	if (versal_nvm_read(&req)) {
		versal_free_read_buffer(&req);
		return TEE_ERROR_GENERIC;
	}

	memcpy(buf, versal_get_read_buffer(&req), EFUSE_IV_LEN);
	versal_free_read_buffer(&req);

	return TEE_SUCCESS;
}

TEE_Result versal_efuse_read_ppk(uint32_t *buf, size_t len,
				 enum versal_nvm_ppk_type type)
{
	struct versal_nvm_read_req req = {
		req.efuse_id = EFUSE_READ_PPK_HASH,
		.ppk_type = type,
	};

	if (len < EFUSE_PPK_LEN)
		return TEE_ERROR_BAD_PARAMETERS;

	if (versal_alloc_read_buffer(&req))
		return TEE_ERROR_OUT_OF_MEMORY;

	if (versal_nvm_read(&req))
		return TEE_ERROR_GENERIC;

	memcpy(buf, versal_get_read_buffer(&req), EFUSE_PPK_LEN);
	versal_free_read_buffer(&req);

	return TEE_SUCCESS;
}

TEE_Result versal_efuse_write_user_data(uint32_t *buf, size_t len,
					uint32_t first, size_t num)
{
	uint32_t lbuf[EFUSE_MAX_USER_FUSES] __aligned_efuse = { 0 };
	struct versal_efuse_user_data cfg __aligned_efuse = {
		.addr = (uintptr_t)lbuf,
		.start = first,
		.num = num,
	};
	struct versal_nvm_write_req __aligned_efuse req = {
		.data.user_fuse_addr = virt_to_phys(&cfg),
		.data.env_mon_dis_flag = 1,
		.efuse_id = EFUSE_WRITE,
	};
	size_t i = 0;

	if (first + num > EFUSE_MAX_USER_FUSES || len  < num * sizeof(uint32_t))
		return TEE_ERROR_BAD_PARAMETERS;

	req.data.user_fuse_addr = virt_to_phys((void *)req.data.user_fuse_addr);
	cfg.addr = virt_to_phys(lbuf);

	req.ibuf[0].buf = &req.data;
	req.ibuf[0].len = sizeof(req.data);
	req.ibuf[1].buf = &cfg;
	req.ibuf[1].len = sizeof(cfg);
	req.ibuf[2].buf = lbuf;
	req.ibuf[2].len = sizeof(lbuf);

	for (i = 0; i < cfg.num; i++)
		lbuf[i] = buf[i];

	return versal_nvm_write(&req);
}

TEE_Result versal_efuse_write_aes_keys(struct versal_efuse_aes_keys *keys)
{
	struct versal_efuse_aes_keys cfg __aligned_efuse = { };
	struct versal_nvm_write_req req __aligned_efuse = {
		.data.aes_key_addr = virt_to_phys(&cfg),
		.data.env_mon_dis_flag = 1,
		.efuse_id = EFUSE_WRITE,
	};

	memcpy(&cfg, keys, sizeof(cfg));

	req.ibuf[0].buf = &req.data;
	req.ibuf[0].len = sizeof(req.data);
	req.ibuf[1].buf = &cfg;
	req.ibuf[1].len = sizeof(cfg);

	return versal_nvm_write(&req);
}

TEE_Result versal_efuse_write_ppk_hash(struct versal_efuse_ppk_hash *hash)
{
	struct versal_efuse_ppk_hash cfg __aligned_efuse = { };
	struct versal_nvm_write_req req __aligned_efuse = {
		.data.ppk_hash_addr = virt_to_phys(&cfg),
		.data.env_mon_dis_flag = 1,
		.efuse_id = EFUSE_WRITE,
	};

	memcpy(&cfg, hash, sizeof(cfg));

	req.ibuf[0].buf = &req.data;
	req.ibuf[0].len = sizeof(req.data);
	req.ibuf[1].buf = &cfg;
	req.ibuf[1].len = sizeof(cfg);

	return versal_nvm_write(&req);
}

TEE_Result versal_efuse_write_iv(struct versal_efuse_ivs *p)
{
	struct versal_efuse_ivs cfg __aligned_efuse = { };
	struct versal_nvm_write_req req __aligned_efuse = {
		.data.iv_addr = virt_to_phys(&cfg),
		.data.env_mon_dis_flag = 1,
		.efuse_id = EFUSE_WRITE,
	};

	memcpy(&cfg, p, sizeof(cfg));

	req.ibuf[0].buf = &req.data;
	req.ibuf[0].len = sizeof(req.data);
	req.ibuf[1].buf = &cfg;
	req.ibuf[1].len = sizeof(cfg);

	return versal_nvm_write(&req);
}

TEE_Result versal_efuse_write_dec_only(struct versal_efuse_dec_only *p)
{
	struct versal_efuse_dec_only cfg __aligned_efuse = { };
	struct versal_nvm_write_req req __aligned_efuse = {
		.data.dec_only_addr = virt_to_phys(&cfg),
		.data.env_mon_dis_flag = 1,
		.efuse_id = EFUSE_WRITE,
	};

	memcpy(&cfg, p, sizeof(cfg));

	req.ibuf[0].buf = &req.data;
	req.ibuf[0].len = sizeof(req.data);
	req.ibuf[1].buf = &cfg;
	req.ibuf[1].len = sizeof(cfg);

	return versal_nvm_write(&req);
}

TEE_Result versal_efuse_write_sec(struct versal_efuse_sec_ctrl_bits *p)
{
	struct versal_efuse_sec_ctrl_bits cfg __aligned_efuse = { };
	struct versal_nvm_write_req req __aligned_efuse = {
		.data.sec_ctrl_addr = virt_to_phys(&cfg),
		.data.env_mon_dis_flag = 1,
		.efuse_id = EFUSE_WRITE,
	};

	memcpy(&cfg, p, sizeof(cfg));

	req.ibuf[0].buf = &req.data;
	req.ibuf[0].len = sizeof(req.data);
	req.ibuf[1].buf = &cfg;
	req.ibuf[1].len = sizeof(cfg);

	return versal_nvm_write(&req);
}

TEE_Result versal_efuse_write_misc(struct versal_efuse_misc_ctrl_bits *p)
{
	struct versal_efuse_misc_ctrl_bits cfg __aligned_efuse = { };
	struct versal_nvm_write_req req __aligned_efuse = {
		.data.misc_ctrl_addr = virt_to_phys(&cfg),
		.data.env_mon_dis_flag = 1,
		.efuse_id = EFUSE_WRITE,
	};

	memcpy(&cfg, p, sizeof(cfg));

	req.ibuf[0].buf = &req.data;
	req.ibuf[0].len = sizeof(req.data);
	req.ibuf[1].buf = &cfg;
	req.ibuf[1].len = sizeof(cfg);

	return versal_nvm_write(&req);
}

TEE_Result versal_efuse_write_glitch_cfg(struct versal_efuse_glitch_cfg_bits *p)
{
	struct versal_efuse_glitch_cfg_bits cfg __aligned_efuse = { };
	struct versal_nvm_write_req req __aligned_efuse = {
		.data.glitch_cfg_addr = virt_to_phys(&cfg),
		.data.env_mon_dis_flag = 1,
		.efuse_id = EFUSE_WRITE,
	};

	memcpy(&cfg, p, sizeof(cfg));

	req.ibuf[0].buf = &req.data;
	req.ibuf[0].len = sizeof(req.data);
	req.ibuf[1].buf = &cfg;
	req.ibuf[1].len = sizeof(cfg);

	return versal_nvm_write(&req);
}

TEE_Result versal_efuse_write_boot_env(struct versal_efuse_boot_env_ctrl_bits
				       *p)
{
	struct versal_efuse_boot_env_ctrl_bits cfg __aligned_efuse = { };
	struct versal_nvm_write_req req __aligned_efuse = {
		.data.boot_env_ctrl_addr = virt_to_phys(&cfg),
		.data.env_mon_dis_flag = 1,
		.efuse_id = EFUSE_WRITE,
	};

	memcpy(&cfg, p, sizeof(cfg));

	req.ibuf[0].buf = &req.data;
	req.ibuf[0].len = sizeof(req.data);
	req.ibuf[1].buf = &cfg;
	req.ibuf[1].len = sizeof(cfg);

	return versal_nvm_write(&req);
}

TEE_Result versal_efuse_write_sec_misc1(struct versal_efuse_sec_misc1_bits *p)
{
	struct versal_efuse_sec_misc1_bits cfg __aligned_efuse = { };
	struct versal_nvm_write_req req __aligned_efuse = {
		.data.misc1_ctrl_addr = virt_to_phys(&cfg),
		.data.env_mon_dis_flag = 1,
		.efuse_id = EFUSE_WRITE,
	};

	memcpy(&cfg, p, sizeof(cfg));

	req.ibuf[0].buf = &req.data;
	req.ibuf[0].len = sizeof(req.data);
	req.ibuf[1].buf = &cfg;
	req.ibuf[1].len = sizeof(cfg);

	return versal_nvm_write(&req);
}

TEE_Result versal_efuse_write_offchip_ids(struct versal_efuse_offchip_ids *p)
{
	struct versal_efuse_offchip_ids cfg __aligned_efuse = { };
	struct versal_nvm_write_req req __aligned_efuse = {
		.data.offchip_id_addr = virt_to_phys(&cfg),
		.data.env_mon_dis_flag = 1,
		.efuse_id = EFUSE_WRITE,
	};

	memcpy(&cfg, p, sizeof(cfg));

	req.ibuf[0].buf = &req.data;
	req.ibuf[0].len = sizeof(req.data);
	req.ibuf[1].buf = &cfg;
	req.ibuf[1].len = sizeof(cfg);

	return versal_nvm_write(&req);
}

TEE_Result versal_efuse_write_revoke_ppk(enum versal_nvm_ppk_type type)
{
	struct versal_efuse_misc_ctrl_bits cfg __aligned_efuse = { };
	struct versal_nvm_write_req req __aligned_efuse = {
		.data.misc_ctrl_addr = virt_to_phys(&cfg),
		.data.env_mon_dis_flag = 1,
		.efuse_id = EFUSE_WRITE,
	};

	req.data.misc_ctrl_addr = virt_to_phys((void *)req.data.misc_ctrl_addr);
	if (type == EFUSE_PPK0)
		cfg.ppk0_invalid = 1;
	else if (type == EFUSE_PPK1)
		cfg.ppk1_invalid = 1;
	else if (type == EFUSE_PPK2)
		cfg.ppk2_invalid = 1;
	else
		return TEE_ERROR_BAD_PARAMETERS;

	req.ibuf[0].buf = &req.data;
	req.ibuf[0].len = sizeof(req.data);
	req.ibuf[1].buf = &cfg;
	req.ibuf[1].len = sizeof(cfg);

	return versal_nvm_write(&req);
}

TEE_Result versal_efuse_write_revoke_id(uint32_t id)
{
	struct versal_efuse_revoke_ids cfg __aligned_efuse = { };
	struct versal_nvm_write_req req __aligned_efuse = {
		.data.revoke_id_addr = virt_to_phys(&cfg),
		.data.env_mon_dis_flag = 1,
		.efuse_id = EFUSE_WRITE,
	};
	uint32_t row = 0;
	uint32_t bit = 0;

	row = id >> (NVM_WORD_LEN + 1);
	bit = id & (NVM_WORD_LEN - 1);

	cfg.revoke_id[row] = BIT(bit);
	cfg.prgm_revoke_id = 1;

	req.ibuf[0].buf = &req.data;
	req.ibuf[0].len = sizeof(req.data);
	req.ibuf[1].buf = &cfg;
	req.ibuf[1].len = sizeof(cfg);

	return versal_nvm_write(&req);
}

TEE_Result versal_efuse_read_revoke_id(uint32_t *buf, size_t len,
				       enum versal_nvm_revocation_id id)
{
	struct versal_nvm_read_req req = {
		.efuse_id = EFUSE_READ_REVOCATION_ID,
		.revocation_id = id,
	};

	if (len < EFUSE_REVOCATION_ID_LEN)
		return TEE_ERROR_BAD_PARAMETERS;

	if (versal_alloc_read_buffer(&req))
		return TEE_ERROR_OUT_OF_MEMORY;

	if (versal_nvm_read(&req)) {
		versal_free_read_buffer(&req);
		return TEE_ERROR_GENERIC;
	}

	memcpy(buf, versal_get_read_buffer(&req), EFUSE_REVOCATION_ID_LEN);
	versal_free_read_buffer(&req);

	return TEE_SUCCESS;
}

TEE_Result versal_efuse_read_misc_ctrl(struct versal_efuse_misc_ctrl_bits *buf)
{
	struct versal_nvm_read_req req = {
		.efuse_id = EFUSE_READ_MISC_CTRL,
	};

	if (versal_alloc_read_buffer(&req))
		return TEE_ERROR_OUT_OF_MEMORY;

	if (versal_nvm_read(&req)) {
		versal_free_read_buffer(&req);
		return TEE_ERROR_GENERIC;
	}

	memcpy(buf, versal_get_read_buffer(&req), sizeof(*buf));
	versal_free_read_buffer(&req);

	return TEE_SUCCESS;
}

TEE_Result versal_efuse_read_sec_ctrl(struct versal_efuse_sec_ctrl_bits *buf)
{
	struct versal_nvm_read_req req = {
		.efuse_id = EFUSE_READ_SEC_CTRL,
	};

	if (versal_alloc_read_buffer(&req))
		return TEE_ERROR_OUT_OF_MEMORY;

	if (versal_nvm_read(&req)) {
		versal_free_read_buffer(&req);
		return TEE_ERROR_GENERIC;
	}

	memcpy(buf, versal_get_read_buffer(&req), sizeof(*buf));
	versal_free_read_buffer(&req);

	return TEE_SUCCESS;
}

TEE_Result versal_efuse_read_sec_misc1(struct versal_efuse_sec_misc1_bits *buf)
{
	struct versal_nvm_read_req req = {
		.efuse_id = EFUSE_READ_SEC_MISC1,
	};

	if (versal_alloc_read_buffer(&req))
		return TEE_ERROR_OUT_OF_MEMORY;

	if (versal_nvm_read(&req)) {
		versal_free_read_buffer(&req);
		return TEE_ERROR_GENERIC;
	}

	memcpy(buf, versal_get_read_buffer(&req), sizeof(*buf));
	versal_free_read_buffer(&req);

	return TEE_SUCCESS;
}

TEE_Result
versal_efuse_read_boot_env_ctrl(struct versal_efuse_boot_env_ctrl_bits *buf)
{
	struct versal_nvm_read_req req = {
		.efuse_id = EFUSE_READ_BOOT_ENV_CTRL,
	};

	if (versal_alloc_read_buffer(&req))
		return TEE_ERROR_OUT_OF_MEMORY;

	if (versal_nvm_read(&req)) {
		versal_free_read_buffer(&req);
		return TEE_ERROR_GENERIC;
	}

	memcpy(buf, versal_get_read_buffer(&req), sizeof(*buf));
	versal_free_read_buffer(&req);

	return TEE_SUCCESS;
}

TEE_Result versal_efuse_read_offchip_revoke_id(uint32_t *buf, size_t len,
					       enum versal_nvm_offchip_id id)
{
	struct versal_nvm_read_req req = {
		.efuse_id = EFUSE_READ_OFFCHIP_REVOCATION_ID,
		.offchip_id = id,
	};

	if (len < EFUSE_OFFCHIP_REVOCATION_ID_LEN)
		return TEE_ERROR_BAD_PARAMETERS;

	if (versal_alloc_read_buffer(&req))
		return TEE_ERROR_OUT_OF_MEMORY;

	if (versal_nvm_read(&req)) {
		versal_free_read_buffer(&req);
		return TEE_ERROR_GENERIC;
	}

	memcpy(buf, versal_get_read_buffer(&req), EFUSE_REVOCATION_ID_LEN);
	versal_free_read_buffer(&req);

	return TEE_SUCCESS;
}

TEE_Result versal_efuse_read_dec_only(uint32_t *buf, size_t len)
{
	struct versal_nvm_read_req req = {
		.efuse_id = EFUSE_READ_DEC_EFUSE_ONLY,
	};

	if (len < EFUSE_DEC_ONLY_LEN)
		return TEE_ERROR_BAD_PARAMETERS;

	if (versal_alloc_read_buffer(&req))
		return TEE_ERROR_OUT_OF_MEMORY;

	if (versal_nvm_read(&req)) {
		versal_free_read_buffer(&req);
		return TEE_ERROR_GENERIC;
	}

	memcpy(buf, versal_get_read_buffer(&req), EFUSE_DEC_ONLY_LEN);
	versal_free_read_buffer(&req);

	return TEE_SUCCESS;
}

TEE_Result
versal_efuse_read_puf_sec_ctrl(struct versal_efuse_puf_sec_ctrl_bits *buf)
{
	struct versal_nvm_read_req req = {
		.efuse_id = EFUSE_READ_PUF_SEC_CTRL,
	};

	if (versal_alloc_read_buffer(&req))
		return TEE_ERROR_OUT_OF_MEMORY;

	if (versal_nvm_read(&req)) {
		versal_free_read_buffer(&req);
		return TEE_ERROR_GENERIC;
	}

	memcpy(buf, versal_get_read_buffer(&req), sizeof(*buf));
	versal_free_read_buffer(&req);

	return TEE_SUCCESS;
}

TEE_Result versal_efuse_read_puf(struct versal_efuse_puf_header *buf)
{
	struct versal_nvm_read_req req = {
		.efuse_id = EFUSE_READ_PUF,
	};

	if (versal_alloc_read_buffer(&req))
		return TEE_ERROR_OUT_OF_MEMORY;

	memcpy(versal_get_read_buffer(&req), buf, sizeof(*buf));

	if (versal_nvm_read(&req)) {
		versal_free_read_buffer(&req);
		return TEE_ERROR_GENERIC;
	}

	memcpy(buf, versal_get_read_buffer(&req), sizeof(*buf));
	versal_free_read_buffer(&req);

	return TEE_SUCCESS;
}

/*
 *  This functionality requires building the PLM with XNVM_ACCESS_PUF_USER_DATA
 *  Calls will fail otherwise.
 *  When available, efuse_read_puf becomes unavailable.
 */
TEE_Result
versal_efuse_read_puf_as_user_fuse(struct versal_efuse_puf_user_fuse *p)
{
	uint32_t fuses[PUF_EFUSES_WORDS]__aligned_efuse = { 0 };
	struct versal_efuse_puf_fuse_addr lbuf __aligned_efuse = {
		.env_monitor_dis = p->env_monitor_dis,
		.prgm_puf_fuse = p->prgm_puf_fuse,
		.start_row = p->start_row,
		.num_rows = p->num_rows,
		.data_addr = virt_to_phys(fuses),
	};
	struct versal_nvm_read_req req = {
		.efuse_id = EFUSE_READ_PUF_USER_FUSES,
	};

	req.ibuf[0].buf = &lbuf;
	req.ibuf[0].len = sizeof(lbuf);
	req.ibuf[1].buf = fuses;
	req.ibuf[1].len = sizeof(fuses);

	if (versal_nvm_read(&req))
		return TEE_ERROR_GENERIC;

	memcpy(p->data_addr, fuses, sizeof(fuses));

	return TEE_SUCCESS;
}

/*
 *  This functionality requires building the PLM with XNVM_ACCESS_PUF_USER_DATA.
 *  Calls will fail otherwise.
 *  When available, efuse_write_puf becomes unavailable.
 */
TEE_Result
versal_efuse_write_puf_as_user_fuse(struct versal_efuse_puf_user_fuse *p)
{
	uint32_t fuses[PUF_EFUSES_WORDS]__aligned_efuse = { 0 };
	struct versal_efuse_puf_fuse_addr lbuf __aligned_efuse  = {
		.env_monitor_dis = p->env_monitor_dis,
		.prgm_puf_fuse = p->prgm_puf_fuse,
		.start_row = p->start_row,
		.num_rows = p->num_rows,
		.data_addr = virt_to_phys(fuses),
	};
	struct versal_nvm_write_req req = {
		.efuse_id = EFUSE_PUF_USER_FUSE_WRITE,
	};

	memcpy(fuses, p->data_addr, sizeof(p->data_addr));

	req.ibuf[0].buf = &lbuf;
	req.ibuf[0].len = sizeof(lbuf);
	req.ibuf[1].buf = fuses;
	req.ibuf[1].len = sizeof(fuses);

	if (versal_nvm_write(&req))
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}

TEE_Result versal_efuse_write_puf(struct versal_efuse_puf_header *buf)
{
	struct versal_efuse_puf_header cfg __aligned_efuse = { };
	struct versal_nvm_write_req req __aligned_efuse = {
		.efuse_id = EFUSE_WRITE_PUF,
	};

	memcpy(&cfg, buf, sizeof(*buf));

	req.ibuf[0].buf = &cfg;
	req.ibuf[0].len = sizeof(cfg);

	if (versal_nvm_write(&req))
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}

TEE_Result versal_bbram_write_aes_key(uint8_t *key, size_t len)
{
	struct versal_nvm_write_req req __aligned_efuse = {
		.efuse_id = BBRAM_WRITE_AES_KEY,
		.bbram.aes_key_len = len,
	};
	void *buf = NULL;

	if (len != 32)
		return TEE_ERROR_BAD_PARAMETERS;

	buf = alloc_cache_aligned(1024);
	if (!buf)
		return TEE_ERROR_OUT_OF_MEMORY;

	memcpy(buf, key, len);

	req.ibuf[0].buf = buf;
	req.ibuf[0].len = 1024;

	if (versal_nvm_write(&req)) {
		free(buf);
		return TEE_ERROR_GENERIC;
	}
	free(buf);

	return TEE_SUCCESS;
}

TEE_Result versal_bbram_zeroize(void)
{
	struct versal_nvm_write_req req __aligned_efuse  = {
		.efuse_id = BBRAM_ZEROIZE,
	};

	if (versal_nvm_write(&req))
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}

TEE_Result versal_bbram_write_user_data(uint32_t data)
{
	struct versal_nvm_write_req req __aligned_efuse = {
		.efuse_id = BBRAM_WRITE_USER_DATA,
		.bbram.user_data = data,
	};

	if (versal_nvm_write(&req))
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}

TEE_Result versal_bbram_read_user_data(uint32_t *data)
{
	struct versal_nvm_read_req req = {
		.efuse_id = BBRAM_READ_USER_DATA,
	};

	if (versal_alloc_read_buffer(&req))
		return TEE_ERROR_OUT_OF_MEMORY;

	if (versal_nvm_read(&req)) {
		versal_free_read_buffer(&req);
		return TEE_ERROR_GENERIC;
	}

	memcpy(data, versal_get_read_buffer(&req), sizeof(*data));
	versal_free_read_buffer(&req);

	return TEE_SUCCESS;
}

TEE_Result versal_bbram_lock_write_user_data(void)
{
	struct versal_nvm_write_req req __aligned_efuse  = {
		.efuse_id = BBRAM_LOCK_WRITE_USER_DATA,
	};

	if (versal_nvm_write(&req))
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}
