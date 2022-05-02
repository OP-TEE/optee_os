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
#include <mm/core_memprot.h>
#include <string.h>
#include <tee/cache.h>

#include "drivers/versal_nvm.h"

/* Protocol API with the remote processor */
#define NVM_MODULE_SHIFT	8
#define NVM_MODULE		11
#define NVM_API_ID(_id) ((NVM_MODULE << NVM_MODULE_SHIFT) | (_id))

/*
 * Max size of the buffer needed for the remote processor to DMA efuse _data_
 * to/from
 */
#define EFUSE_MAX_LEN (EFUSE_MAX_USER_FUSES * sizeof(uint32_t))

enum versal_nvm_api_id {
	API_FEATURES			= 0,
	BBRAM_WRITE_AES_KEY		= 1,
	BBRAM_ZEROIZE			= 2,
	BBRAM_WRITE_USER_DATA		= 3,
	BBRAM_READ_USER_DATA		= 4,
	BBRAM_LOCK_WRITE_USER_DATA	= 5,
	EFUSE_WRITE			= 6,
	EFUSE_WRITE_PUF			= 7,
	EFUSE_PUF_USER_FUSE_WRITE	= 8,
	EFUSE_READ_IV			= 9,
	EFUSE_READ_REVOCATION_ID	= 10,
	EFUSE_READ_OFFCHIP_REVOCATION_ID = 11,
	EFUSE_READ_USER_FUSES		= 12,
	EFUSE_READ_MISC_CTRL		= 13,
	EFUSE_READ_SEC_CTRL		= 14,
	EFUSE_READ_SEC_MISC1		= 15,
	EFUSE_READ_BOOT_ENV_CTRL	= 16,
	EFUSE_READ_PUF_SEC_CTRL		= 17,
	EFUSE_READ_PPK_HASH		= 18,
	EFUSE_READ_DEC_EFUSE_ONLY	= 19,
	EFUSE_READ_DNA			= 20,
	EFUSE_READ_PUF_USER_FUSES	= 21,
	EFUSE_READ_PUF			= 22,
	EFUSE_INVALID			= 23,
};

struct versal_efuse_sec_ctrl_bits {
	uint8_t aes_dis;
	uint8_t jtag_err_out_dis;
	uint8_t jtag_dis;
	uint8_t ppk0_wr_lk;
	uint8_t ppk1_wr_lk;
	uint8_t ppk2_wr_lk;
	uint8_t aes_crc_lk;
	uint8_t aes_wr_lk;
	uint8_t user_key0_crc_lk;
	uint8_t user_key0_wr_lk;
	uint8_t user_key1_crc_lk;
	uint8_t user_key1_wr_lk;
	uint8_t sec_dbg_dis;
	uint8_t sec_lock_dbg_dis;
	uint8_t boot_env_wr_lk;
	uint8_t reg_init_dis;
	uint8_t pad[48];
} __packed;

struct versal_efuse_puf_sec_ctrl_bits {
	uint8_t puf_regen_dis;
	uint8_t puf_hd_invalid;
	uint8_t puf_test2_dis;
	uint8_t puf_dis;
	uint8_t puf_syn_lk;
	uint8_t pad[59];
} __packed;

struct versal_efuse_misc_ctrl_bits {
	uint8_t glitch_det_halt_boot_en;
	uint8_t glitch_det_rom_monitor_en;
	uint8_t halt_boot_error;
	uint8_t halt_boot_env;
	uint8_t vrypto_kat_en;
	uint8_t lbist_en;
	uint8_t safety_mission_en;
	uint8_t ppk0_invalid;
	uint8_t ppk1_invalid;
	uint8_t ppk2_invalid;
	uint8_t pad[54];
} __packed;

struct versal_efuse_sec_misc1_bits {
	uint8_t lpd_mbist_en;
	uint8_t pmc_mbist_en;
	uint8_t lpd_noc_sc_en;
	uint8_t sysmon_volt_mon_en;
	uint8_t sysmon_temp_mon_en;
	uint8_t pad[59];
} __packed;

struct versal_efuse_boot_env_ctrl_bits {
	uint8_t prgm_sysmon_temp_hot;
	uint8_t prgm_sysmon_volt_pmc;
	uint8_t prgm_sysmon_volt_pslp;
	uint8_t prgm_sysmon_temp_cold;
	uint8_t sysmon_temp_en;
	uint8_t sysmon_volt_en;
	uint8_t sysmon_volt_soc;
	uint8_t sysmon_temp_hot;
	uint8_t sysmon_volt_pmc;
	uint8_t sysmon_volt_pslp;
	uint8_t sysmon_temp_cold;
	uint8_t pad[53];
} __packed;

struct versal_efuse_glitch_cfg_bits {
	uint8_t prgm_glitch;
	uint8_t glitch_det_wr_lk;
	uint32_t glitch_det_trim;
	uint8_t gd_rom_monitor_en;
	uint8_t gd_halt_boot_en;
	uint8_t pad[56];
} __packed;

struct versal_efuse_aes_keys {
	uint8_t prgm_aes_key;
	uint8_t prgm_user_key0;
	uint8_t prgm_user_key1;
	uint32_t aes_key[8];
	uint32_t user_key0[8];
	uint32_t user_key1[8];
	uint8_t pad[29];
} __packed;

struct versal_efuse_ppk_hash {
	uint8_t prgm_ppk0_hash;
	uint8_t prgm_ppk1_hash;
	uint8_t prgm_ppk2_hash;
	uint32_t ppk0_hash[8];
	uint32_t ppk1_hash[8];
	uint32_t ppk2_hash[8];
	uint8_t pad[29];
} __packed;

struct versal_efuse_dec_only {
	uint8_t prgm_dec_only;
	uint8_t pad[63];
} __packed;

struct versal_efuse_revoke_ids {
	uint8_t prgm_revoke_id;
	uint32_t revoke_id[8];
	uint8_t pad[31];
} __packed;

struct versal_efuse_offchip_ids {
	uint8_t prgm_offchip_id;
	uint32_t offchip_id[8];
	uint8_t pad[31];
} __packed;

struct versal_efuse_ivs {
	uint8_t prgm_meta_header_iv;
	uint8_t prgm_blk_obfus_iv;
	uint8_t prgm_plm_iv;
	uint8_t prgm_data_partition_iv;
	uint32_t meta_header_iv[3];
	uint32_t blk_obfus_iv[3];
	uint32_t plm_iv[3];
	uint32_t data_partition_iv[3];
	uint8_t pad[12];
} __packed;

struct versal_efuse_user_data {
	uint32_t start;
	uint32_t num;
	uint64_t addr;
	uint8_t pad[48];
} __packed;

struct versal_efuse_puf_fuse {
	uint8_t env_monitor_dis;
	uint8_t prgm_puf_fuse;
	uint32_t start;
	uint32_t num;
	uint64_t addr;
	uint8_t pad[46];
} __packed;

struct versal_efuse_puf_hd {
	struct versal_efuse_puf_sec_ctrl_bits puf_sec_ctrl_bits;
	uint8_t prgm_puf_helper_data;
	uint8_t env_monitor_dis;
	uint32_t efuse_syn_data[127];
	uint32_t chash;
	uint32_t aux;
	uint8_t pad[58];
} __packed;

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
} __packed;

/* Helper read and write requests (not part of the protocol) */
struct versal_nvm_read_req {
	enum versal_nvm_api_id efuse_id;
	enum versal_nvm_revocation_id revocation_id;
	enum versal_nvm_offchip_id offchip_id;
	enum versal_nvm_ppk_type ppk_type;
	enum versal_nvm_iv_type iv_type;
	struct ipi_buf ibuf[MAX_IPI_BUF];
};

enum versal_nvm_write_efuse_id {
	EFUSE_WRITE_USER_FUSES = 0,
	EFUSE_WRITE_INVALID = 0xffff,
};

struct versal_nvm_write_req {
	struct versal_efuse_data data;
	enum versal_nvm_write_efuse_id id;
	struct ipi_buf ibuf[MAX_IPI_BUF];
};

struct cmd_args {
	uint32_t data[3];
	size_t len;
};

static TEE_Result prepare_cmd(struct ipi_cmd *cmd, enum versal_nvm_api_id efuse,
			      struct ipi_buf *ibufs, struct cmd_args *arg)
{
	size_t i = 0;

	cmd->data[i++] = NVM_API_ID(efuse);
	for (i = 1; i < arg->len + 1; i++)
		cmd->data[i] = arg->data[i];

	if (!ibufs[0].p)
		return TEE_SUCCESS;

	cmd->data[i++] = virt_to_phys(ibufs[0].p);
	cmd->data[i++] = virt_to_phys(ibufs[0].p) >> 32;

	for (i = 0; i < MAX_IPI_BUF; i++) {
		cmd->ibuf[i].len = ibufs[i].len;
		cmd->ibuf[i].p = ibufs[i].p;
	}

	return TEE_SUCCESS;
}

static TEE_Result efuse_req(enum versal_nvm_api_id efuse, struct ipi_buf *ibufs,
			    struct cmd_args *arg)
{
	TEE_Result ret = TEE_SUCCESS;
	struct ipi_cmd cmd = { };

	ret = prepare_cmd(&cmd, efuse, ibufs, arg);
	if (ret)
		return ret;

	ret = versal_mbox_notify(&cmd, NULL);
	if (ret)
		EMSG("Mailbox error");

	return ret;
}

static TEE_Result versal_nvm_read(struct versal_nvm_read_req *req)
{
	struct cmd_args args = { };

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
	case BBRAM_READ_USER_DATA:
	case EFUSE_READ_USER_FUSES:
	case EFUSE_READ_PUF_USER_FUSES:
	case EFUSE_READ_PUF:
		break;
	case BBRAM_ZEROIZE:
	case BBRAM_LOCK_WRITE_USER_DATA:
		if (req->ibuf[0].p)
			return TEE_ERROR_GENERIC;
		break;
	case EFUSE_READ_OFFCHIP_REVOCATION_ID:
		args.data[0] = req->offchip_id;
		args.len = 1;
		break;
	case EFUSE_READ_REVOCATION_ID:
		args.data[0] = req->revocation_id;
		args.len = 1;
		break;
	case EFUSE_READ_IV:
		args.data[0] = req->iv_type;
		args.len = 1;
		break;
	case EFUSE_READ_PPK_HASH:
		args.data[0] = req->ppk_type;
		args.len = 1;
		break;
	default:
		return TEE_ERROR_GENERIC;
	}

	return efuse_req(req->efuse_id, req->ibuf, &args);
}

static TEE_Result versal_nvm_write(struct versal_nvm_write_req *req)
{
	enum versal_nvm_api_id efuse_id = EFUSE_INVALID;
	struct cmd_args args = { };

	switch (req->id) {
	case EFUSE_WRITE_USER_FUSES:
		efuse_id = EFUSE_WRITE;
		break;
	default:
		return TEE_ERROR_GENERIC;
	}

	return efuse_req(efuse_id, req->ibuf, &args);
}

TEE_Result versal_read_efuse_dna(uint32_t *buf, size_t len)
{
	uint8_t lbuf[EFUSE_MAX_LEN] __aligned_efuse = { 0 };
	struct versal_nvm_read_req req = { 0 };

	if (len < EFUSE_DNA_LEN)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Prepare request */
	req.efuse_id = EFUSE_READ_DNA;

	/* Request cache management */
	req.ibuf[0].p = lbuf;
	req.ibuf[0].len = sizeof(lbuf);

	if (versal_nvm_read(&req))
		return TEE_ERROR_GENERIC;

	memcpy(buf, lbuf, EFUSE_DNA_LEN);

	return TEE_SUCCESS;
}

TEE_Result versal_read_efuse_user(uint32_t *buf, size_t len, uint32_t first,
				  size_t num)
{
	uint8_t lbuf[EFUSE_MAX_LEN] __aligned_efuse = { 0 };
	struct versal_efuse_user_data cfg __aligned_efuse = {
		.addr = (uintptr_t)lbuf,
		.start = first,
		.num = num, /* fuses needs to be at least 40 bytes */
	};
	struct versal_nvm_read_req req = { 0 };

	if (first + num > EFUSE_MAX_USER_FUSES || len < num * sizeof(uint32_t))
		return TEE_ERROR_BAD_PARAMETERS;

	/* Prepare request */
	req.efuse_id = EFUSE_READ_USER_FUSES;

	/* Request cache management */
	req.ibuf[0].p = &cfg;
	req.ibuf[0].len = sizeof(cfg);
	req.ibuf[1].p = lbuf;
	req.ibuf[1].len = sizeof(lbuf);

	/* Update the command buffer */
	cfg.addr = (paddr_t)virt_to_phys((void *)cfg.addr);

	if (versal_nvm_read(&req))
		return TEE_ERROR_GENERIC;

	memcpy(buf, lbuf, num * sizeof(uint32_t));

	return TEE_SUCCESS;
}

TEE_Result versal_read_efuse_iv(uint32_t *buf, size_t len,
				enum versal_nvm_iv_type type)
{
	uint8_t lbuf[EFUSE_MAX_LEN] __aligned_efuse = { 0 };
	struct versal_nvm_read_req req = { .iv_type = type, };

	if (len < EFUSE_IV_LEN)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Prepare the request */
	req.efuse_id = EFUSE_READ_IV;

	/* Request cache management */
	req.ibuf[0].p = lbuf;
	req.ibuf[0].len = sizeof(lbuf);

	if (versal_nvm_read(&req))
		return TEE_ERROR_GENERIC;

	memcpy(buf, lbuf, EFUSE_IV_LEN);

	return TEE_SUCCESS;
}

TEE_Result versal_read_efuse_ppk(uint32_t *buf, size_t len,
				 enum versal_nvm_ppk_type type)
{
	uint8_t lbuf[EFUSE_MAX_LEN]__aligned_efuse = { 0 };
	struct versal_nvm_read_req req = { .ppk_type = type, };

	if (len < EFUSE_PPK_LEN)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Prepare the request */
	req.efuse_id = EFUSE_READ_PPK_HASH;

	/* Request cache management */
	req.ibuf[0].p = lbuf;
	req.ibuf[0].len = sizeof(lbuf);

	if (versal_nvm_read(&req))
		return TEE_ERROR_GENERIC;

	memcpy(buf, lbuf, EFUSE_PPK_LEN);

	return TEE_SUCCESS;
}

TEE_Result versal_write_efuse_user(uint32_t *buf, size_t len, uint32_t first,
				   size_t num)
{
	uint32_t lbuf[EFUSE_MAX_USER_FUSES] __aligned_efuse = { 0 };
	struct versal_efuse_user_data cfg __aligned_efuse = {
		.addr = (uintptr_t)lbuf,
		.start = first,
		.num = num,
	};
	struct versal_nvm_write_req req __aligned_efuse = {
		.data.env_mon_dis_flag = 1,
		.data.user_fuse_addr = (uintptr_t)&cfg,
		.id = EFUSE_WRITE_USER_FUSES,
	};
	size_t i = 0;

	if (first + num > EFUSE_MAX_USER_FUSES || len  < num * sizeof(uint32_t))
		return TEE_ERROR_BAD_PARAMETERS;

	/* Update the command buffers with physical addresses */
	req.data.user_fuse_addr = (paddr_t)
				  virt_to_phys((void *)req.data.user_fuse_addr);
	cfg.addr = (paddr_t)virt_to_phys(lbuf);

	/* Request cache management */
	req.ibuf[0].p = &req.data;
	req.ibuf[0].len = sizeof(req.data);
	req.ibuf[1].p = &cfg;
	req.ibuf[1].len = sizeof(cfg);
	req.ibuf[2].p = lbuf;
	req.ibuf[2].len = sizeof(lbuf);

	/* Prepare fuses to write with some random data */
	for (i = 0; i < cfg.num; i++)
		lbuf[i] = buf[i];

	return versal_nvm_write(&req);
}
