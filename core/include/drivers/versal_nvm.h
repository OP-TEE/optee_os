/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2022 Foundries.io Ltd
 */

#ifndef __DRIVERS_VERSAL_NVM_H__
#define __DRIVERS_VERSAL_NVM_H__

#include <drivers/versal_mbox.h>
#include <platform_config.h>
#include <tee_api_types.h>
#include <types_ext.h>
#include <util.h>

#define PUF_EFUSES_WORDS		(128)
#define PUF_SYN_DATA_WORDS		(127)
#define EFUSE_MAX_USER_FUSES		(64)

#define EFUSE_OFFCHIP_REVOCATION_ID_LEN	(4)
#define EFUSE_REVOCATION_ID_LEN		(4)
#define EFUSE_DEC_ONLY_LEN		(4)
#define EFUSE_DNA_LEN			(16)
#define EFUSE_PPK_LEN			(32)
#define EFUSE_IV_LEN			(12)

enum versal_nvm_iv_type {
	EFUSE_META_HEADER_IV_RANGE = 0,
	EFUSE_BLACK_IV,
	EFUSE_PLM_IV_RANGE,
	EFUSE_DATA_PARTITION_IV_RANGE,
};

enum versal_nvm_ppk_type {
	EFUSE_PPK0 = 0,
	EFUSE_PPK1,
	EFUSE_PPK2
};

enum versal_nvm_revocation_id {
	EFUSE_REVOCATION_ID_0 = 0,
	EFUSE_REVOCATION_ID_1,
	EFUSE_REVOCATION_ID_2,
	EFUSE_REVOCATION_ID_3,
	EFUSE_REVOCATION_ID_4,
	EFUSE_REVOCATION_ID_5,
	EFUSE_REVOCATION_ID_6,
	EFUSE_REVOCATION_ID_7
};

enum versal_nvm_offchip_id {
	EFUSE_INVLD = -1,
	EFUSE_OFFCHIP_REVOKE_ID_0 = 0,
	EFUSE_OFFCHIP_REVOKE_ID_1,
	EFUSE_OFFCHIP_REVOKE_ID_2,
	EFUSE_OFFCHIP_REVOKE_ID_3,
	EFUSE_OFFCHIP_REVOKE_ID_4,
	EFUSE_OFFCHIP_REVOKE_ID_5,
	EFUSE_OFFCHIP_REVOKE_ID_6,
	EFUSE_OFFCHIP_REVOKE_ID_7
};

/*
 * All structures mapped to the PLM processor must be address_and_size aligned
 * to the cacheline_len.
 */

struct versal_efuse_glitch_cfg_bits {
	uint8_t prgm_glitch;
	uint8_t glitch_det_wr_lk;
	uint32_t glitch_det_trim;
	uint8_t gd_rom_monitor_en;
	uint8_t gd_halt_boot_en;
	uint8_t pad[53];
};

struct versal_efuse_aes_keys {
	uint8_t prgm_aes_key;
	uint8_t prgm_user_key0;
	uint8_t prgm_user_key1;
	uint32_t aes_key[8];
	uint32_t user_key0[8];
	uint32_t user_key1[8];
	uint8_t pad[25];
};

struct versal_efuse_ppk_hash {
	uint8_t prgm_ppk0_hash;
	uint8_t prgm_ppk1_hash;
	uint8_t prgm_ppk2_hash;
	uint32_t ppk0_hash[8];
	uint32_t ppk1_hash[8];
	uint32_t ppk2_hash[8];
	uint8_t pad[89];
};

struct versal_efuse_dec_only {
	uint8_t prgm_dec_only;
	uint8_t pad[63];
};

struct versal_efuse_revoke_ids {
	uint8_t prgm_revoke_id;
	uint32_t revoke_id[8];
	uint8_t pad[89];
};

struct versal_efuse_offchip_ids {
	uint8_t prgm_offchip_id;
	uint32_t offchip_id[8];
	uint8_t pad[89];
};

struct versal_efuse_user_data {
	uint32_t start;
	uint32_t num;
	uint64_t addr;
	uint8_t pad[48];
};

struct versal_efuse_puf_fuse {
	uint8_t env_monitor_dis;
	uint8_t prgm_puf_fuse;
	uint32_t start;
	uint32_t num;
	uint64_t addr;
	uint8_t pad[104];
};

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
};

struct versal_efuse_misc_ctrl_bits {
	uint8_t glitch_det_halt_boot_en;
	uint8_t glitch_det_rom_monitor_en;
	uint8_t halt_boot_error;
	uint8_t halt_boot_env;
	uint8_t crypto_kat_en;
	uint8_t lbist_en;
	uint8_t safety_mission_en;
	uint8_t ppk0_invalid;
	uint8_t ppk1_invalid;
	uint8_t ppk2_invalid;
	uint8_t pad[54];
};

struct versal_efuse_puf_sec_ctrl_bits {
	uint8_t puf_regen_dis;
	uint8_t puf_hd_invalid;
	uint8_t puf_test2_dis;
	uint8_t puf_dis;
	uint8_t puf_syn_lk;
	uint8_t pad[59];
};

struct versal_efuse_sec_misc1_bits {
	uint8_t lpd_mbist_en;
	uint8_t pmc_mbist_en;
	uint8_t lpd_noc_sc_en;
	uint8_t sysmon_volt_mon_en;
	uint8_t sysmon_temp_mon_en;
	uint8_t pad[59];
};

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
};

struct versal_efuse_puf_header {
	struct versal_efuse_puf_sec_ctrl_bits sec_ctrl;
	uint8_t prmg_puf_helper_data;
	uint8_t env_monitor_dis;
	uint32_t efuse_syn_data[PUF_SYN_DATA_WORDS];
	uint32_t chash;
	uint32_t aux;
	uint8_t pad[56];
};

struct versal_efuse_puf_user_fuse {
	uint32_t data_addr[PUF_EFUSES_WORDS];
	uint8_t env_monitor_dis;
	uint8_t prgm_puf_fuse;
	uint32_t start_row;
	uint32_t num_rows;
};

TEE_Result versal_efuse_read_dna(uint32_t *buf, size_t len);
TEE_Result versal_efuse_read_user_data(uint32_t *buf, size_t len,
				       uint32_t first, size_t num);
TEE_Result versal_efuse_read_iv(uint32_t *buf, size_t len,
				enum versal_nvm_iv_type type);
TEE_Result versal_efuse_read_ppk(uint32_t *buf, size_t len,
				 enum versal_nvm_ppk_type type);
TEE_Result versal_efuse_write_user_data(uint32_t *buf, size_t len,
					uint32_t first, size_t num);
TEE_Result versal_efuse_write_aes_keys(struct versal_efuse_aes_keys *keys);
TEE_Result versal_efuse_write_ppk_hash(struct versal_efuse_ppk_hash *hash);
TEE_Result versal_efuse_write_iv(struct versal_efuse_ivs *p);
TEE_Result versal_efuse_write_dec_only(struct versal_efuse_dec_only *p);
TEE_Result versal_efuse_write_sec(struct versal_efuse_sec_ctrl_bits *p);
TEE_Result versal_efuse_write_misc(struct versal_efuse_misc_ctrl_bits *p);
TEE_Result versal_efuse_write_glitch_cfg(struct versal_efuse_glitch_cfg_bits
					 *p);
TEE_Result versal_efuse_write_boot_env(struct versal_efuse_boot_env_ctrl_bits
				       *p);
TEE_Result versal_efuse_write_sec_misc1(struct versal_efuse_sec_misc1_bits *p);
TEE_Result versal_efuse_write_offchip_ids(struct versal_efuse_offchip_ids *p);
TEE_Result versal_efuse_write_revoke_ppk(enum versal_nvm_ppk_type type);
TEE_Result versal_efuse_write_revoke_id(uint32_t id);
TEE_Result versal_efuse_read_revoke_id(uint32_t *buf, size_t len,
				       enum versal_nvm_revocation_id id);
TEE_Result versal_efuse_read_misc_ctrl(struct versal_efuse_misc_ctrl_bits *buf);
TEE_Result versal_efuse_read_sec_ctrl(struct versal_efuse_sec_ctrl_bits *buf);
TEE_Result versal_efuse_read_sec_misc1(struct versal_efuse_sec_misc1_bits *buf);
TEE_Result
versal_efuse_read_boot_env_ctrl(struct versal_efuse_boot_env_ctrl_bits *buf);
TEE_Result versal_efuse_read_offchip_revoke_id(uint32_t *buf, size_t len,
					       enum versal_nvm_offchip_id id);
TEE_Result versal_efuse_read_dec_only(uint32_t *buf, size_t len);
TEE_Result versal_efuse_read_puf_sec_ctrl(struct versal_efuse_puf_sec_ctrl_bits
					  *buf);
TEE_Result versal_efuse_read_puf(struct versal_efuse_puf_header *buf);
TEE_Result versal_efuse_read_puf_as_user_fuse(struct versal_efuse_puf_user_fuse
					      *p);
TEE_Result versal_efuse_write_puf_as_user_fuse(struct versal_efuse_puf_user_fuse
					       *p);
TEE_Result versal_efuse_write_puf(struct versal_efuse_puf_header *buf);
TEE_Result versal_bbram_write_aes_key(uint8_t *key, size_t len);
TEE_Result versal_bbram_zeroize(void);
TEE_Result versal_bbram_write_user_data(uint32_t data);
TEE_Result versal_bbram_read_user_data(uint32_t *data);
TEE_Result versal_bbram_lock_write_user_data(void);

#endif /*__DRIVERS_VERSAL_NVM_H__*/
