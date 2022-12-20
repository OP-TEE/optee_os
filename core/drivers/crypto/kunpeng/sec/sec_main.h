/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2022, HiSilicon Limited
 */
#ifndef __SEC_MAIN_H
#define __SEC_MAIN_H

#include "qm.h"

/*
 * Version number maintenance rule:
 * first.second.third: year.month.change num
 */
#define SEC_MODULE_VERSION "22.11.2"

#ifdef CFG_HISILICON_ACC_V3
#define SEC_BAR 0x160000000
#else
#define SEC_BAR 0x141800000
#endif
#define SEC_SIZE 0x400000

#define SEC_SQE_SIZE 128
#define SEC_SQE_LOG2_SIZE 7

#define SEC_PF_ABNORMAL_INT_SOURCE_REG 0x0010
#define SEC_NFE_ERROR_MASK  0x24
#define SEC_SQE_ICV_SHIFT 1
#define SEC_SQE_FLAG_SHIFT 7
#define SEC_MAC_TO_DDR 0x1
#define SEC_PBKDF2 0x8
#define MAC_LEN	   0x8
#define MAC_LEN_HMAC_SHA224 0x7
#define AUTH_KEY_LEN  0x8
#define C_NUM		 10000
#define PASS_WORD_LEN 0x20
#define GET_IMG_ROTKEY_AP 0x6
#define SEC_PBKDF2_SUCC 0x81
#define SEC_HW_TASK_DONE	0x1
#define SQE_BYTES_NUMS		128
#define SEC_USE_HUK 0x1
#define AES_KEYSIZE_128	 16
#define AES_KEYSIZE_192	 24
#define AES_KEYSIZE_256	 32
#define XTS_KEYSIZE_256	 64
#define XTS_KEYSIZE_128	 32
#define XTS_CKEY_LEN_128_BIT 0
#define XTS_CKEY_LEN_256_BIT 2

#define TYPE_ENCRYPTIN 0
#define SEC_CIPHER_THEN_DIGEST	0
#define SEC_DIGEST_THEN_CIPHER	1

#define ECB_CBC_SRC_ALIGN_MASK 0xf
#define CTR_SRC_ALIGN_MASK 0xf
#define CTR_SRC_BLOCK_SIZE 0x10
#define BYTE_BITS 0x8

struct hisi_sec_sqe_type2 {
	uint32_t nonce_len : 4;
	uint32_t huk : 1;
	uint32_t key_s : 1;
	uint32_t ci_gen : 2;
	uint32_t ai_gen : 2;
	uint32_t a_pad : 2;
	uint32_t c_s : 2;
	uint32_t rsvd1 : 2;
	uint32_t rhf : 1;
	uint32_t c_key_type : 2;
	uint32_t a_key_type : 2;
	uint32_t write_frame_len : 3;
	uint32_t cal_iv_addr_en : 1;
	uint32_t tls_up : 1;
	uint32_t rsvd0 : 5;
	uint32_t inveld : 1;
	uint32_t mac_len : 5;
	uint32_t a_key_len : 6;
	uint32_t a_alg : 6;
	uint32_t rsvd3 : 15;
	uint32_t c_icv_len : 6;
	uint32_t c_width : 3;
	uint32_t c_key_len : 3;
	uint32_t c_mode : 4;
	uint32_t c_alg : 4;
	uint32_t rsvd4 : 12;
	uint32_t a_len : 24;
	uint32_t iv_offset_l : 8;
	uint32_t c_len : 24;
	uint32_t iv_offset_h : 8;
	uint32_t auth_src_offset : 16;
	uint32_t cipher_src_offset : 16;
	uint32_t cs_ip_header_offset : 16;
	uint32_t cs_udp_header_offset : 16;
	uint32_t pass_word_len : 16;
	uint32_t dk_len : 16;
	uint32_t salt3 : 8;
	uint32_t salt2 : 8;
	uint32_t salt1 : 8;
	uint32_t salt0 : 8;
	uint32_t tag : 16;
	uint32_t rsvd5 : 16;
	uint32_t c_pad_type : 4;
	uint32_t c_pad_len : 8;
	uint32_t c_pad_data_type : 4;
	uint32_t c_pad_len_field : 2;
	uint32_t rsvd6 : 14;
	uint32_t long_a_data_len_l;
	uint32_t long_a_data_len_h;
	uint32_t a_ivin_addr_l;
	uint32_t a_ivin_addr_h;
	uint32_t a_key_addr_l;
	uint32_t a_key_addr_h;
	uint32_t mac_addr_l;
	uint32_t mac_addr_h;
	uint32_t c_ivin_addr_l;
	uint32_t c_ivin_addr_h;
	uint32_t c_key_addr_l;
	uint32_t c_key_addr_h;
	uint32_t data_src_addr_l;
	uint32_t data_src_addr_h;
	uint32_t data_dst_addr_l;
	uint32_t data_dst_addr_h;
	uint32_t done : 1;
	uint32_t icv : 3;
	uint32_t rsvd11 : 3;
	uint32_t flag : 4;
	uint32_t rsvd10 : 5;
	uint32_t error_type : 8;
	uint32_t warning_type : 8;
	uint32_t mac_i3 : 8;
	uint32_t mac_i2 : 8;
	uint32_t mac_i1 : 8;
	uint32_t mac_i0 : 8;
	uint32_t check_sum_i : 16;
	uint32_t tls_pad_len_i : 8;
	uint32_t rsvd12 : 8;
	uint32_t counter;
};

struct hisi_sec_sqe {
	uint32_t type : 4;
	uint32_t cipher : 2;
	uint32_t auth : 2;
	uint32_t seq : 1;
	uint32_t de : 2;
	uint32_t scene : 4;
	uint32_t src_addr_type : 3;
	uint32_t dst_addr_type : 3;
	uint32_t mac_addr_type : 3;
	uint32_t rsvd0 : 8;
	struct hisi_sec_sqe_type2 type2;
};

struct bd3_auth_key_iv {
	uint32_t a_key_addr_l;
	uint32_t a_key_addr_h;
	uint32_t a_ivin_addr_l;
	uint32_t a_ivin_addr_h;
	uint32_t rsvd0;
	uint32_t rsvd1;
};

struct bd3_ipsec_scene {
	uint32_t c_ivin_addr_l;
	uint32_t c_ivin_addr_h;
	uint32_t c_s : 2;
	uint32_t deal_esp_ah : 4;
	uint32_t protocol_type : 4;
	uint32_t mode : 2;
	uint32_t ip_type : 2;
	uint32_t mac_sel : 1;
	uint32_t rsvd0 : 1;
	uint32_t next_header : 8;
	uint32_t pad_len : 8;
	uint32_t iv_offset : 16;
	uint32_t rsvd1 : 16;
	uint32_t cs_ip_header_offset : 16;
	uint32_t cs_udp_header_offset : 16;
};

struct bd3_pbkdf2_scene {
	uint32_t c_ivin_addr_l;
	uint32_t c_ivin_addr_h;
	uint32_t pbkdf2_salt_len : 24;
	uint32_t rsvd0 : 8;
	uint32_t c_num : 24;
	uint32_t rsvd1 : 8;
	uint32_t pass_word_len : 16;
	uint32_t dk_len : 16;
};

struct bd3_stream_scene {
	uint32_t c_ivin_addr_l;
	uint32_t c_ivin_addr_h;
	uint32_t long_a_data_len_l;
	uint32_t long_a_data_len_h;
	uint32_t auth_pad : 2;
	uint32_t stream_protocol : 3;
	uint32_t mac_sel : 1;
	uint32_t rsvd0 : 2;
	uint32_t plaintext_type : 8;
	uint32_t pad_len_1p3 : 16;
};

struct bd3_check_sum {
	uint32_t check_sum_i : 16;
	uint32_t tls_pad_len_i : 8;
	uint32_t rsvd0 : 8;
};

struct hisi_sec_bd3_sqe {
	uint32_t type : 4;
	uint32_t inveld : 1;
	uint32_t scene : 4;
	uint32_t de : 2;
	uint32_t src_addr_type : 3;
	uint32_t dst_addr_type : 3;
	uint32_t mac_addr_type : 3;
	uint32_t rsvd : 12;

	uint32_t cipher : 2;
	uint32_t ci_gen : 2;
	uint32_t c_icv_len : 6;
	uint32_t c_width : 3;
	uint32_t c_key_len : 3;
	uint32_t c_mode : 4;
	uint32_t c_alg : 4;
	uint32_t nonce_len : 4;
	uint32_t rsv : 1;
	uint32_t cal_iv_addr_en : 1;
	uint32_t seq : 1;
	uint32_t rsvd0 : 1;

	uint32_t tag_l;
	uint32_t tag_h;
	uint32_t data_src_addr_l;
	uint32_t data_src_addr_h;

	struct bd3_auth_key_iv auth_key_iv;

	uint32_t c_key_addr_l;
	uint32_t c_key_addr_h;
	uint32_t auth : 2;
	uint32_t ai_gen : 2;
	uint32_t mac_len : 5;
	uint32_t a_key_len : 6;
	uint32_t a_alg : 6;
	uint32_t key_sel : 4;
	uint32_t ctr_counter_mode : 2;
	uint32_t sva_prefetch : 1;
	uint32_t key_wrap_num : 3;
	uint32_t update_key : 1;

	uint32_t salt3 : 8;
	uint32_t salt2 : 8;
	uint32_t salt1 : 8;
	uint32_t salt0 : 8;
	uint32_t auth_src_offset : 16;
	uint32_t cipher_src_offset : 16;
	uint32_t a_len : 24;
	uint32_t auth_key_offset : 8;
	uint32_t c_len : 24;
	uint32_t auth_ivin_offset : 8;
	uint32_t data_dst_addr_l;
	uint32_t data_dst_addr_h;
	uint32_t mac_addr_l;
	uint32_t mac_addr_h;

	union {
		struct bd3_ipsec_scene ipsec_scene;
		struct bd3_pbkdf2_scene pbkdf2_scene;
		struct bd3_stream_scene stream_scene;
	};

	uint32_t done : 1;
	uint32_t icv : 3;
	uint32_t csc : 3;
	uint32_t flag : 4;
	uint32_t dc : 3;
	uint32_t rsvd10 : 2;
	uint32_t error_type : 8;
	uint32_t warning_type : 8;
	union {
		uint32_t mac_i;
		uint32_t kek_key_addr_l;
	};
	union {
		uint32_t kek_key_addr_h;
		struct bd3_check_sum check_sum;
	};
	uint32_t counter;
};

enum {
	NO_CIPHER,
	CIPHER_ENCRYPT,
	CIPHER_DECRYPT,
	REPORT_COPY,
};

enum sec_bd_type {
	BD_TYPE1 = 0x1,
	BD_TYPE2 = 0x2,
	BD_TYPE3 = 0x3,
};

enum CKEY_LEN {
	CKEY_LEN_128_BIT = 0x0,
	CKEY_LEN_192_BIT = 0x1,
	CKEY_LEN_256_BIT = 0x2,
	CKEY_LEN_SM4	 = 0x0,
	CKEY_LEN_DES	 = 0x1,
	CKEY_LEN_3DES_3KEY = 0x1,
	CKEY_LEN_3DES_2KEY = 0x3,
};

enum {
	SCENE_NOTHING = 0x0,
	SCENE_IPSEC = 0x1,
	SCENE_SSL_TLS = 0x3,
	SCENE_DTLS = 0x4,
	SCENE_STORAGE = 0x5,
	SCENE_NAS = 0x6,
	SCENE_STREAM = 0x7,
	SCENE_PBKDF2 = 0x8,
	SCENE_SMB = 0x9,
};

enum {
	DATA_DST_ADDR_DISABLE,
	DATA_DST_ADDR_ENABLE,
};

enum hisi_buff_type {
	HISI_FLAT_BUF,
	HISI_SGL_BUF,
};

struct hisi_qp *sec_create_qp(uint8_t sq_type);

#endif
