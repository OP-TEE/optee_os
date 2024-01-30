// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2022 Foundries.io Ltd
 * Jorge Ramirez-Ortiz <jorge@foundries.io>
 */

#include <arm.h>
#include <drivers/versal_mbox.h>
#include <drivers/versal_nvm.h>
#include <initcall.h>
#include <io.h>
#include <kernel/panic.h>
#include <kernel/tee_misc.h>
#include <mm/core_memprot.h>
#include <string.h>
#include <tee/cache.h>

#define NVM_WORD_LEN 4

/* Protocol API with the remote processor */
#define NVM_MODULE_SHIFT		8
#define NVM_MODULE			11
#define NVM_API_ID(_id) (SHIFT_U32(NVM_MODULE, NVM_MODULE_SHIFT) | (_id))

#define __aligned_efuse			__aligned(CACHELINE_LEN)

#define EFUSE_CACHE_DNA_OFFSET				0x20
#define EFUSE_CACHE_BOOT_ENV_CTRL_OFFSET		0x94
#define EFUSE_CACHE_MISC_CTRL_OFFSET			0xA0
#define EFUSE_CACHE_PUF_ECC_CTRL_OFFSET			0xA4
#define EFUSE_CACHE_PUF_CHASH_OFFSET			0xA8
#define EFUSE_CACHE_SEC_CTRL_OFFSET			0xAC
#define EFUSE_CACHE_REVOCATION_ID0_OFFSET		0xB0
#define EFUSE_CACHE_SEC_MISC0_OFFSET			0xE4
#define EFUSE_CACHE_SEC_MISC1_OFFSET			0xE8
#define EFUSE_CACHE_PPK0_OFFSET				0x100
#define EFUSE_CACHE_PPK1_OFFSET				0x120
#define EFUSE_CACHE_PPK2_OFFSET				0x140
#define EFUSE_CACHE_OFFCHIP_REVOKE_ID0_OFFSET		0x160
#define EFUSE_CACHE_METAHEADER_IV_RANGE0_OFFSET		0x180
#define EFUSE_CACHE_BLACK_IV0_OFFSET			0x1D0
#define EFUSE_CACHE_PLM_IV_RANGE0_OFFSET		0x1DC
#define EFUSE_CACHE_DATA_PARTITION_IV_RANGE0_OFFSET	0x1E8
#define EFUSE_CACHE_USER0_OFFSET			0x240
#define EFUSE_CACHE_PUF_SYN0_OFFSET			0x300

#define EFUSE_ENV_DIS_FLAG		0

#define EFUSE_AES_KEY_ID		0
#define EFUSE_USER_KEY0_ID		1
#define EFUSE_USER_KEY1_ID		2

#define EFUSE_WRITE_PUF_DATA_WORDS (PUF_SYN_DATA_WORDS + 6)

/*
 * Max size of the buffer needed for the remote processor to DMA efuse _data_
 * to/from
 */
#define EFUSE_MAX_LEN (EFUSE_MAX_USER_FUSES * sizeof(uint32_t))

/* Internal */
struct versal_efuse_puf_fuse_addr {
	uint64_t data_addr;
	uint32_t start_row;
	uint32_t num_rows;
	uint8_t env_monitor_dis;
	uint8_t prgm_puf_fuse;
	uint8_t pad[46];
};

enum versal_nvm_api_id {
	API_FEATURES			= 0,
	BBRAM_WRITE_AES_KEY		= 1,
	BBRAM_ZEROIZE			= 2,
	BBRAM_WRITE_USER_DATA		= 3,
	BBRAM_READ_USER_DATA		= 4,
	BBRAM_LOCK_WRITE_USER_DATA	= 5,
	BBRAM_WRITE_AES_KEY_FROM_PLOAD	= 6,
	EFUSE_WRITE_AES_KEY		= 7,
	EFUSE_WRITE_AES_KEY_FROM_PLOAD	= 8,
	EFUSE_WRITE_PPK_HASH		= 9,
	EFUSE_WRITE_PPK_HASH_FROM_PLOAD	= 10,
	EFUSE_WRITE_IV			= 11,
	EFUSE_WRITE_IV_FROM_PLOAD	= 12,
	EFUSE_WRITE_GLITCH_CONFIG	= 13,
	EFUSE_WRITE_DEC_ONLY		= 14,
	EFUSE_WRITE_REVOCATION_ID	= 15,
	EFUSE_WRITE_OFFCHIP_REVOKE_ID	= 16,
	EFUSE_WRITE_MISC_CTRL_BITS	= 17,
	EFUSE_WRITE_SEC_CTRL_BITS	= 18,
	EFUSE_WRITE_MISC1_CTRL_BITS	= 19,
	EFUSE_WRITE_BOOT_ENV_CTRL_BITS	= 20,
	EFUSE_WRITE_FIPS_INFO		= 21,
	EFUSE_WRITE_UDS_FROM_PLOAD	= 22,
	EFUSE_WRITE_DME_KEY_FROM_PLOAD	= 23,
	EFUSE_WRITE_DME_REVOKE		= 24,
	EFUSE_WRITE_PLM_UPDATE		= 25,
	EFUSE_WRITE_BOOT_MODE_DISABLE	= 26,
	EFUSE_WRITE_CRC			= 27,
	EFUSE_WRITE_DME_MODE		= 28,
	EFUSE_WRITE_PUF_HD_FROM_PLOAD	= 29,
	EFUSE_WRITE_PUF			= 30,
	EFUSE_WRITE_ROM_RSVD		= 31,
	EFUSE_WRITE_PUF_CTRL_BITS	= 32,
	EFUSE_READ_CACHE		= 33,
	EFUSE_RELOAD_N_PRGM_PROT_BITS	= 34,
	EFUSE_INVALID			= 35,
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

	ret = versal_mbox_notify_pmc(&cmd, NULL, NULL);
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
	req->ibuf[0].buf = NULL;
}

static void *versal_get_read_buffer(struct versal_nvm_read_req *req)
{
	assert(req);
	return req->ibuf[0].buf;
}

static TEE_Result versal_nvm_read(struct versal_nvm_read_req *req)
{
	if (!req)
		return TEE_ERROR_GENERIC;

	switch (req->efuse_id) {
	case EFUSE_READ_CACHE:
	case BBRAM_READ_USER_DATA:
		break;
	default:
		return TEE_ERROR_GENERIC;
	}

	return efuse_req(req->efuse_id, req->ibuf, NULL);
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
	case BBRAM_ZEROIZE:
		break;
	default:
		return TEE_ERROR_GENERIC;
	}

	return efuse_req(req->efuse_id, req->ibuf, arg);
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

static TEE_Result versal_efuse_read_cache(uint16_t off, uint16_t num,
					  uint32_t *buf, size_t len)
{
	struct versal_ipi_cmd cmd = { };
	struct versal_mbox_mem p = { };
	TEE_Result ret = TEE_SUCCESS;
	uint32_t a = 0;
	uint32_t b = 0;

	if (!buf)
		return TEE_ERROR_BAD_PARAMETERS;

	if (len < num * NVM_WORD_LEN)
		return TEE_ERROR_BAD_PARAMETERS;

	ret = versal_mbox_alloc(num * NVM_WORD_LEN, NULL, &p);
	if (ret)
		return ret;

	reg_pair_from_64(virt_to_phys(p.buf), &b, &a);

	cmd.data[0] = NVM_API_ID(EFUSE_READ_CACHE);
	cmd.data[1] = SHIFT_U32(num, 16) | off;
	cmd.data[2] = a;
	cmd.data[3] = b;

	cmd.ibuf[0].mem = p;

	ret = versal_mbox_notify_pmc(&cmd, NULL, NULL);
	if (ret)
		EMSG("Mailbox error");
	else
		memcpy(buf, p.buf, num * NVM_WORD_LEN);

	versal_mbox_free(&p);
	return ret;
}

TEE_Result versal_efuse_read_dna(uint32_t *buf, size_t len)
{
	if (len < EFUSE_DNA_LEN)
		return TEE_ERROR_BAD_PARAMETERS;

	return versal_efuse_read_cache(EFUSE_CACHE_DNA_OFFSET,
				       EFUSE_DNA_LEN / NVM_WORD_LEN, buf, len);
}

TEE_Result versal_efuse_read_user_data(uint32_t *buf, size_t len,
				       uint32_t first, size_t num)
{
	uint16_t offset = 0;

	if (first + num > EFUSE_MAX_USER_FUSES || len < num * NVM_WORD_LEN)
		return TEE_ERROR_BAD_PARAMETERS;

	offset = EFUSE_CACHE_USER0_OFFSET + first * NVM_WORD_LEN;

	return versal_efuse_read_cache(offset, num, buf, len);
}

TEE_Result versal_efuse_read_iv(uint32_t *buf, size_t len,
				enum versal_nvm_iv_type type)
{
	uint16_t offset = 0;

	switch (type) {
	case EFUSE_META_HEADER_IV_RANGE:
		offset = EFUSE_CACHE_METAHEADER_IV_RANGE0_OFFSET;
		break;
	case EFUSE_BLACK_IV:
		offset = EFUSE_CACHE_BLACK_IV0_OFFSET;
		break;
	case EFUSE_PLM_IV_RANGE:
		offset = EFUSE_CACHE_PLM_IV_RANGE0_OFFSET;
		break;
	case EFUSE_DATA_PARTITION_IV_RANGE:
		offset = EFUSE_CACHE_DATA_PARTITION_IV_RANGE0_OFFSET;
		break;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}

	return versal_efuse_read_cache(offset, EFUSE_IV_LEN / NVM_WORD_LEN,
				       buf, len);
}

TEE_Result versal_efuse_read_ppk(uint32_t *buf, size_t len,
				 enum versal_nvm_ppk_type type)
{
	uint16_t offset = 0;

	switch (type) {
	case EFUSE_PPK0:
		offset = EFUSE_CACHE_PPK0_OFFSET;
		break;
	case EFUSE_PPK1:
		offset = EFUSE_CACHE_PPK1_OFFSET;
		break;
	case EFUSE_PPK2:
		offset = EFUSE_CACHE_PPK2_OFFSET;
		break;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}

	return versal_efuse_read_cache(offset, EFUSE_PPK_LEN / NVM_WORD_LEN,
				       buf, len);
}

TEE_Result versal_efuse_read_revoke_id(uint32_t *buf, size_t len, uint32_t id)
{
	uint32_t reg = EFUSE_CACHE_REVOCATION_ID0_OFFSET;

	if (id < VERSAL_NET_REVOKE_EFUSE_MIN ||
	    id > VERSAL_NET_REVOKE_EFUSE_MAX)
		return TEE_ERROR_BAD_PARAMETERS;

	reg += (id - 1) / 8;

	return versal_efuse_read_cache(reg,
				       EFUSE_REVOCATION_ID_LEN / NVM_WORD_LEN,
				       buf, len);
}

TEE_Result versal_efuse_read_misc_ctrl(struct versal_efuse_misc_ctrl_bits *buf)
{
	TEE_Result ret = TEE_SUCCESS;
	uint32_t misc_ctrl = 0;

	if (!buf)
		return TEE_ERROR_BAD_PARAMETERS;

	ret = versal_efuse_read_cache(EFUSE_CACHE_MISC_CTRL_OFFSET, 1,
				      &misc_ctrl, sizeof(misc_ctrl));
	if (ret)
		return ret;

	buf->glitch_det_halt_boot_en = (misc_ctrl & GENMASK_32(31, 30)) >> 30;
	buf->glitch_det_rom_monitor_en = (misc_ctrl & BIT(29)) >> 29;
	buf->halt_boot_error = (misc_ctrl & GENMASK_32(22, 21)) >> 21;
	buf->halt_boot_env = (misc_ctrl & GENMASK_32(20, 19)) >> 19;
	buf->crypto_kat_en = (misc_ctrl & BIT(15)) >> 15;
	buf->lbist_en = (misc_ctrl & BIT(14)) >> 14;
	buf->safety_mission_en = (misc_ctrl & BIT(8)) >> 8;
	buf->ppk0_invalid = (misc_ctrl & GENMASK_32(7, 6)) >> 6;
	buf->ppk1_invalid = (misc_ctrl & GENMASK_32(5, 4)) >> 4;
	buf->ppk2_invalid = (misc_ctrl & GENMASK_32(3, 2)) >> 2;

	return TEE_SUCCESS;
}

TEE_Result versal_efuse_read_sec_ctrl(struct versal_efuse_sec_ctrl_bits *buf)
{
	TEE_Result ret = TEE_SUCCESS;
	uint32_t sec_ctrl = 0;

	if (!buf)
		return TEE_ERROR_BAD_PARAMETERS;

	ret = versal_efuse_read_cache(EFUSE_CACHE_SEC_CTRL_OFFSET, 1,
				      &sec_ctrl, sizeof(sec_ctrl));
	if (ret)
		return ret;

	buf->aes_dis = sec_ctrl & BIT(0);
	buf->jtag_err_out_dis = (sec_ctrl & BIT(1)) >> 1;
	buf->jtag_dis = (sec_ctrl & BIT(2)) >> 2;
	buf->ppk0_wr_lk = (sec_ctrl & BIT(6)) >> 6;
	buf->ppk1_wr_lk = (sec_ctrl & BIT(7)) >> 7;
	buf->ppk2_wr_lk = (sec_ctrl & BIT(8)) >> 8;
	buf->aes_crc_lk = (sec_ctrl & GENMASK_32(10, 9)) >> 9;
	buf->aes_wr_lk = (sec_ctrl & BIT(11)) >> 11;
	buf->user_key0_crc_lk = (sec_ctrl & BIT(12)) >> 12;
	buf->user_key0_wr_lk = (sec_ctrl & BIT(13)) >> 13;
	buf->user_key1_crc_lk = (sec_ctrl & BIT(14)) >> 14;
	buf->user_key1_wr_lk = (sec_ctrl & BIT(15)) >> 15;
	buf->sec_dbg_dis = (sec_ctrl & GENMASK_32(20, 19)) >> 19;
	buf->sec_lock_dbg_dis = (sec_ctrl & GENMASK_32(22, 21)) >> 21;
	buf->boot_env_wr_lk = (sec_ctrl & BIT(28)) >> 28;
	buf->reg_init_dis = (sec_ctrl & GENMASK_32(31, 30)) >> 30;

	return TEE_SUCCESS;
}

TEE_Result versal_efuse_read_sec_misc1(struct versal_efuse_sec_misc1_bits *buf)
{
	TEE_Result ret = TEE_SUCCESS;
	uint32_t sec_misc1 = 0;

	if (!buf)
		return TEE_ERROR_BAD_PARAMETERS;

	ret = versal_efuse_read_cache(EFUSE_CACHE_SEC_MISC1_OFFSET, 1,
				      &sec_misc1, sizeof(sec_misc1));
	if (ret)
		return ret;

	buf->lpd_mbist_en = (sec_misc1 & GENMASK_32(12, 10)) >> 10;
	buf->pmc_mbist_en = (sec_misc1 & GENMASK_32(9, 7)) >> 7;
	buf->lpd_noc_sc_en = (sec_misc1 & GENMASK_32(6, 4)) >> 4;
	buf->sysmon_volt_mon_en = (sec_misc1 & GENMASK_32(3, 2)) >> 2;
	buf->sysmon_temp_mon_en = sec_misc1 & GENMASK_32(1, 0);

	return TEE_SUCCESS;
}

TEE_Result
versal_efuse_read_boot_env_ctrl(struct versal_efuse_boot_env_ctrl_bits *buf)
{
	TEE_Result ret = TEE_SUCCESS;
	uint32_t boot_env_ctrl = 0;

	if (!buf)
		return TEE_ERROR_BAD_PARAMETERS;

	ret = versal_efuse_read_cache(EFUSE_CACHE_BOOT_ENV_CTRL_OFFSET, 1,
				      &boot_env_ctrl, sizeof(boot_env_ctrl));
	if (ret)
		return ret;

	buf->sysmon_temp_en = (boot_env_ctrl & BIT(21)) >> 21;
	buf->sysmon_volt_en = (boot_env_ctrl & BIT(20)) >> 20;
	buf->sysmon_temp_hot = (boot_env_ctrl & GENMASK_32(18, 17)) >> 17;
	buf->sysmon_volt_pmc = (boot_env_ctrl & GENMASK_32(13, 12)) >> 12;
	buf->sysmon_volt_pslp = (boot_env_ctrl & GENMASK_32(11, 10)) >> 10;
	buf->sysmon_volt_soc = (boot_env_ctrl & GENMASK_32(9, 8)) >> 8;
	buf->sysmon_temp_cold = boot_env_ctrl & GENMASK_32(1, 0);

	return TEE_SUCCESS;
}

TEE_Result versal_efuse_read_offchip_revoke_id(uint32_t *buf, size_t len,
					       uint32_t id)
{
	uint32_t reg = EFUSE_CACHE_OFFCHIP_REVOKE_ID0_OFFSET;

	if (id < VERSAL_NET_REVOKE_EFUSE_MIN ||
	    id > VERSAL_NET_REVOKE_EFUSE_MAX)
		return TEE_ERROR_BAD_PARAMETERS;

	reg += (id - 1) / 8;

	return versal_efuse_read_cache(reg,
				       EFUSE_REVOCATION_ID_LEN / NVM_WORD_LEN,
				       buf, len);
}

TEE_Result versal_efuse_read_dec_only(uint32_t *buf, size_t len)
{
	TEE_Result ret = TEE_SUCCESS;
	uint32_t sec_misc0 = 0;

	if (len < EFUSE_DEC_ONLY_LEN)
		return TEE_ERROR_BAD_PARAMETERS;

	ret = versal_efuse_read_cache(EFUSE_CACHE_SEC_MISC0_OFFSET, 1,
				      &sec_misc0, sizeof(sec_misc0));
	if (ret)
		return ret;

	sec_misc0 &= GENMASK_32(15, 0);

	memcpy(buf, &sec_misc0, EFUSE_DEC_ONLY_LEN);

	return TEE_SUCCESS;
}

TEE_Result versal_efuse_read_puf_sec_ctrl(struct versal_efuse_puf_sec_ctrl_bits
					  *buf)
{
	TEE_Result ret = TEE_SUCCESS;
	uint32_t puf_ctrl = 0;
	uint32_t sec_ctrl = 0;

	if (!buf)
		return TEE_ERROR_BAD_PARAMETERS;

	ret = versal_efuse_read_cache(EFUSE_CACHE_PUF_ECC_CTRL_OFFSET, 1,
				      &puf_ctrl, sizeof(puf_ctrl));
	if (ret)
		return ret;

	/*
	 * Some fuses have moved from PUF_ECC_CTRL to SECURITY_CTRL
	 */
	ret = versal_efuse_read_cache(EFUSE_CACHE_SEC_CTRL_OFFSET, 1,
				      &sec_ctrl, sizeof(sec_ctrl));
	if (ret)
		return ret;

	buf->puf_regen_dis = (puf_ctrl & BIT(31)) >> 31;
	buf->puf_hd_invalid = (puf_ctrl & BIT(30)) >> 30;
	buf->puf_test2_dis = (puf_ctrl & BIT(29)) >> 29;
	buf->puf_dis = (sec_ctrl & BIT(18)) >> 18;
	buf->puf_syn_lk = (sec_ctrl & BIT(16)) >> 16;

	return TEE_SUCCESS;
}

TEE_Result versal_efuse_read_puf(struct versal_efuse_puf_header *buf)
{
	TEE_Result ret = TEE_SUCCESS;

	if (!buf)
		return TEE_ERROR_BAD_PARAMETERS;

	ret = versal_efuse_read_puf_sec_ctrl(&buf->sec_ctrl);
	if (ret)
		return ret;

	ret = versal_efuse_read_cache(EFUSE_CACHE_SEC_CTRL_OFFSET, 1,
				      &buf->aux, sizeof(uint32_t));
	if (ret)
		return ret;

	buf->aux &= GENMASK_32(23, 0);

	ret = versal_efuse_read_cache(EFUSE_CACHE_PUF_CHASH_OFFSET, 1,
				      &buf->chash, sizeof(uint32_t));
	if (ret)
		return ret;

	return versal_efuse_read_cache(EFUSE_CACHE_PUF_SYN0_OFFSET,
				      PUF_SYN_DATA_WORDS, buf->efuse_syn_data,
				      PUF_SYN_DATA_WORDS * NVM_WORD_LEN);
}

TEE_Result
versal_efuse_read_puf_as_user_fuse(struct versal_efuse_puf_user_fuse
				   *p __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result versal_efuse_write_user_data(uint32_t *buf __unused,
					size_t len __unused,
					uint32_t first __unused,
					size_t num __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

static TEE_Result do_write_efuses_buffer(enum versal_nvm_api_id id,
					 uint16_t type, uint32_t *buf,
					 size_t len)
{
	struct versal_ipi_cmd cmd = { };
	struct versal_mbox_mem p = { };
	TEE_Result ret = TEE_SUCCESS;
	uint32_t a = 0;
	uint32_t b = 0;

	ret = versal_mbox_alloc(len, buf, &p);
	if (ret)
		return ret;

	reg_pair_from_64(virt_to_phys(p.buf), &b, &a);

	cmd.data[0] = NVM_API_ID(id);
	cmd.data[1] = SHIFT_U32(type, 16) | EFUSE_ENV_DIS_FLAG;
	cmd.data[2] = a;
	cmd.data[3] = b;

	cmd.ibuf[0].mem = p;

	ret = versal_mbox_notify_pmc(&cmd, NULL, NULL);

	versal_mbox_free(&p);
	return ret;
}

static TEE_Result do_write_efuses_value(enum versal_nvm_api_id id, uint32_t val)
{
	struct versal_ipi_cmd cmd = { };

	cmd.data[0] = NVM_API_ID(id);
	cmd.data[1] = EFUSE_ENV_DIS_FLAG;
	cmd.data[2] = val;

	return versal_mbox_notify_pmc(&cmd, NULL, NULL);
}

static TEE_Result do_write_efuses(enum versal_nvm_api_id id)
{
	return do_write_efuses_value(id, 0);
}

TEE_Result versal_efuse_write_aes_keys(struct versal_efuse_aes_keys *keys)
{
	TEE_Result res = TEE_SUCCESS;
	TEE_Result res2 = TEE_SUCCESS;

	if (!keys)
		return TEE_ERROR_BAD_PARAMETERS;

	if (keys->prgm_aes_key) {
		res2 = do_write_efuses_buffer(EFUSE_WRITE_AES_KEY,
					      EFUSE_AES_KEY_ID,
					      keys->aes_key, EFUSE_AES_KEY_LEN);
		if (res2) {
			DMSG("Error programming AES key (0x%" PRIx32 ")", res2);
			res = TEE_ERROR_GENERIC;
		}
	}

	if (keys->prgm_user_key0) {
		res2 = do_write_efuses_buffer(EFUSE_WRITE_AES_KEY,
					      EFUSE_USER_KEY0_ID,
					      keys->user_key0,
					      EFUSE_AES_KEY_LEN);
		if (res2) {
			DMSG("Error programming User key 0 (0x%" PRIx32 ")",
			     res2);
			res = TEE_ERROR_GENERIC;
		}
	}

	if (keys->prgm_user_key1) {
		res2 = do_write_efuses_buffer(EFUSE_WRITE_AES_KEY,
					      EFUSE_USER_KEY1_ID,
					      keys->user_key1,
					      EFUSE_AES_KEY_LEN);
		if (res2) {
			DMSG("Error programming User key 1 (0x%" PRIx32 ")",
			     res2);
			res = TEE_ERROR_GENERIC;
		}
	}

	return res;
}

TEE_Result versal_efuse_write_ppk_hash(struct versal_efuse_ppk_hash *hash)
{
	TEE_Result res = TEE_SUCCESS;
	TEE_Result res2 = TEE_SUCCESS;

	if (!hash)
		return TEE_ERROR_BAD_PARAMETERS;

	if (hash->prgm_ppk0_hash) {
		res2 = do_write_efuses_buffer(EFUSE_WRITE_PPK_HASH, EFUSE_PPK0,
					      hash->ppk0_hash, EFUSE_PPK_LEN);
		if (res2) {
			DMSG("Error programming PPK hash 0 (0x%" PRIx32 ")",
			     res2);
			res = TEE_ERROR_GENERIC;
		}
	}

	if (hash->prgm_ppk1_hash) {
		res2 = do_write_efuses_buffer(EFUSE_WRITE_PPK_HASH, EFUSE_PPK1,
					      hash->ppk1_hash, EFUSE_PPK_LEN);
		if (res2) {
			DMSG("Error programming PPK hash 1 (0x%" PRIx32 ")",
			     res2);
			res = TEE_ERROR_GENERIC;
		}
	}

	if (hash->prgm_ppk2_hash) {
		res2 = do_write_efuses_buffer(EFUSE_WRITE_PPK_HASH, EFUSE_PPK2,
					      hash->ppk2_hash, EFUSE_PPK_LEN);
		if (res2) {
			DMSG("Error programming PPK hash 2 (0x%" PRIx32 ")",
			     res2);
			res = TEE_ERROR_GENERIC;
		}
	}

	return res;
}

TEE_Result versal_efuse_write_iv(struct versal_efuse_ivs *p)
{
	TEE_Result res = TEE_SUCCESS;
	TEE_Result res2 = TEE_SUCCESS;

	if (!p)
		return TEE_ERROR_BAD_PARAMETERS;

	if (p->prgm_meta_header_iv) {
		res2 = do_write_efuses_buffer(EFUSE_WRITE_IV,
					      EFUSE_META_HEADER_IV_RANGE,
					      p->meta_header_iv, EFUSE_IV_LEN);
		if (res2) {
			DMSG("Error programming meta header IV (0x%" PRIx32 ")",
			     res2);
			res = TEE_ERROR_GENERIC;
		}
	}

	if (p->prgm_blk_obfus_iv) {
		res2 = do_write_efuses_buffer(EFUSE_WRITE_IV, EFUSE_BLACK_IV,
					      p->blk_obfus_iv, EFUSE_IV_LEN);
		if (res2) {
			DMSG("Error programming black IV (0x%" PRIx32 ")",
			     res2);
			res = TEE_ERROR_GENERIC;
		}
	}

	if (p->prgm_plm_iv) {
		res2 = do_write_efuses_buffer(EFUSE_WRITE_IV,
					      EFUSE_PLM_IV_RANGE,
					      p->plm_iv, EFUSE_IV_LEN);
		if (res2) {
			DMSG("Error programming plm IV (0x%" PRIx32 ")", res2);
			res = TEE_ERROR_GENERIC;
		}
	}

	if (p->prgm_data_partition_iv) {
		res2 = do_write_efuses_buffer(EFUSE_WRITE_IV,
					      EFUSE_DATA_PARTITION_IV_RANGE,
					      p->data_partition_iv,
					      EFUSE_IV_LEN);
		if (res2) {
			DMSG("Error programming data IV (0x%" PRIx32 ")", res2);
			res = TEE_ERROR_GENERIC;
		}
	}

	return res;
}

TEE_Result versal_efuse_write_dec_only(struct versal_efuse_dec_only *p)
{
	if (!p)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!p->prgm_dec_only)
		return TEE_SUCCESS;

	return do_write_efuses(EFUSE_WRITE_DEC_ONLY);
}

TEE_Result versal_efuse_write_sec(struct versal_efuse_sec_ctrl_bits *p)
{
	uint32_t val = 0;

	if (!p)
		return TEE_ERROR_BAD_PARAMETERS;

	val = SHIFT_U32(p->reg_init_dis & 0x3, 30) |
	      SHIFT_U32(p->boot_env_wr_lk & 0x1, 28) |
	      SHIFT_U32(p->sec_lock_dbg_dis & 0x3, 21) |
	      SHIFT_U32(p->sec_dbg_dis & 0x3, 19) |
	      SHIFT_U32(p->user_key1_wr_lk & 0x1, 15) |
	      SHIFT_U32(p->user_key1_crc_lk & 0x1, 14) |
	      SHIFT_U32(p->user_key0_wr_lk & 0x1, 13) |
	      SHIFT_U32(p->user_key0_crc_lk & 0x1, 12) |
	      SHIFT_U32(p->aes_wr_lk & 0x1, 11) |
	      SHIFT_U32(p->aes_crc_lk & 0x3, 9) |
	      SHIFT_U32(p->ppk2_wr_lk & 0x1, 8) |
	      SHIFT_U32(p->ppk1_wr_lk & 0x1, 7) |
	      SHIFT_U32(p->ppk0_wr_lk & 0x1, 6) |
	      SHIFT_U32(p->jtag_dis & 0x1, 2) |
	      SHIFT_U32(p->jtag_err_out_dis & 0x1, 1) |
	      (p->aes_dis & 0x1);

	return do_write_efuses_value(EFUSE_WRITE_SEC_CTRL_BITS, val);
}

TEE_Result versal_efuse_write_misc(struct versal_efuse_misc_ctrl_bits *p)
{
	uint32_t val = 0;

	if (!p)
		return TEE_ERROR_BAD_PARAMETERS;

	val = SHIFT_U32(p->glitch_det_halt_boot_en & 0x3, 30) |
	      SHIFT_U32(p->glitch_det_rom_monitor_en & 0x1, 29) |
	      SHIFT_U32(p->halt_boot_error & 0x3, 21) |
	      SHIFT_U32(p->halt_boot_env & 0x3, 19) |
	      SHIFT_U32(p->crypto_kat_en & 0x1, 15) |
	      SHIFT_U32(p->lbist_en & 0x1, 14) |
	      SHIFT_U32(p->safety_mission_en & 0x1, 8) |
	      SHIFT_U32(p->ppk2_invalid & 0x3, 6) |
	      SHIFT_U32(p->ppk1_invalid & 0x3, 4) |
	      SHIFT_U32(p->ppk0_invalid & 0x3, 2);

	return do_write_efuses_value(EFUSE_WRITE_MISC_CTRL_BITS, val);
}

TEE_Result
versal_efuse_write_glitch_cfg(struct versal_efuse_glitch_cfg_bits *p)
{
	uint32_t val = 0;

	if (!p)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!p->prgm_glitch)
		return TEE_SUCCESS;

	val = SHIFT_U32(p->glitch_det_wr_lk & 0x1, 31) | p->glitch_det_trim;

	return do_write_efuses_value(EFUSE_WRITE_GLITCH_CONFIG, val);
}

TEE_Result
versal_efuse_write_boot_env(struct versal_efuse_boot_env_ctrl_bits *p)
{
	uint32_t val = 0;

	if (!p)
		return TEE_ERROR_BAD_PARAMETERS;

	val = SHIFT_U32(p->sysmon_temp_en & 0x1, 21) |
	      SHIFT_U32(p->sysmon_volt_en & 0x1, 20) |
	      SHIFT_U32(p->sysmon_temp_hot & 0x3, 17) |
	      SHIFT_U32(p->sysmon_volt_pmc & 0x3, 12) |
	      SHIFT_U32(p->sysmon_volt_pslp & 0x3, 10) |
	      SHIFT_U32(p->sysmon_volt_soc & 0x3, 8) |
	      (p->sysmon_temp_cold & 0x2);

	return do_write_efuses_value(EFUSE_WRITE_BOOT_ENV_CTRL_BITS, val);
}

TEE_Result versal_efuse_write_sec_misc1(struct versal_efuse_sec_misc1_bits *p)
{
	uint32_t val = 0;

	if (!p)
		return TEE_ERROR_BAD_PARAMETERS;

	val = SHIFT_U32(p->lpd_mbist_en & 0x7, 10) |
	      SHIFT_U32(p->pmc_mbist_en & 0x7, 7) |
	      SHIFT_U32(p->lpd_noc_sc_en & 0x7, 4) |
	      SHIFT_U32(p->sysmon_volt_mon_en & 0x3, 2) |
	      (p->sysmon_temp_mon_en & 0x3);

	return do_write_efuses_value(EFUSE_WRITE_MISC1_CTRL_BITS, val);
}

/*
 * versal_efuse_write_offchip_ids expects an efuse identifier between
 * 1 and 256.
 */
TEE_Result versal_efuse_write_offchip_ids(uint32_t id)
{
	if (id < VERSAL_NET_REVOKE_EFUSE_MIN ||
	    id > VERSAL_NET_REVOKE_EFUSE_MAX)
		return TEE_ERROR_BAD_PARAMETERS;

	return do_write_efuses_value(EFUSE_WRITE_OFFCHIP_REVOKE_ID, id);
}

TEE_Result versal_efuse_write_revoke_ppk(enum versal_nvm_ppk_type type)
{
	struct versal_efuse_misc_ctrl_bits misc_ctrl = {};

	switch (type) {
	case EFUSE_PPK0:
		misc_ctrl.ppk0_invalid = 0x3;
		break;
	case EFUSE_PPK1:
		misc_ctrl.ppk1_invalid = 0x3;
		break;
	case EFUSE_PPK2:
		misc_ctrl.ppk2_invalid = 0x3;
		break;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}

	return versal_efuse_write_misc(&misc_ctrl);
}

/*
 * versal_efuse_write_revoke_id expects an efuse identifier between
 * 1 and 256.
 */
TEE_Result versal_efuse_write_revoke_id(uint32_t id)
{
	if (id < VERSAL_NET_REVOKE_EFUSE_MIN ||
	    id > VERSAL_NET_REVOKE_EFUSE_MAX)
		return TEE_ERROR_BAD_PARAMETERS;

	return do_write_efuses_value(EFUSE_WRITE_REVOCATION_ID, id);
}

TEE_Result versal_efuse_write_puf_as_user_fuse(struct versal_efuse_puf_user_fuse
					       *p __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

struct versal_efuse_write_puf_data {
	uint32_t sec_ctrl;
	uint32_t prgm_puf_helper_data;
	uint32_t env_monitor_dis;
	uint32_t syn[PUF_SYN_DATA_WORDS];
	uint32_t chash;
	uint32_t aux;
	uint32_t ro_swap;
};

TEE_Result versal_efuse_write_puf(struct versal_efuse_puf_header *buf)
{
	struct versal_ipi_cmd cmd = { };
	struct versal_mbox_mem p = { };
	TEE_Result ret = TEE_SUCCESS;
	uint32_t a = 0;
	uint32_t b = 0;
	struct versal_efuse_write_puf_data *data = NULL;

	if (!buf)
		return TEE_ERROR_BAD_PARAMETERS;

	ret = versal_mbox_alloc(EFUSE_WRITE_PUF_DATA_WORDS * NVM_WORD_LEN,
				NULL, &p);
	if (ret)
		return ret;

	data = p.buf;

	data->sec_ctrl = 0;
	data->prgm_puf_helper_data = buf->prmg_puf_helper_data;
	data->env_monitor_dis = buf->env_monitor_dis;
	memcpy(data->syn, buf->efuse_syn_data,
	       PUF_SYN_DATA_WORDS * NVM_WORD_LEN);
	data->chash = buf->chash;
	data->aux = buf->aux;
	data->ro_swap = 0;

	reg_pair_from_64(virt_to_phys(p.buf), &b, &a);

	cmd.data[0] = NVM_API_ID(EFUSE_WRITE_PUF);
	cmd.data[2] = a;
	cmd.data[3] = b;

	cmd.ibuf[0].mem = p;

	ret = versal_mbox_notify_pmc(&cmd, NULL, NULL);

	versal_mbox_free(&p);
	return ret;
}
