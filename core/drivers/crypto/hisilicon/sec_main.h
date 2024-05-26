/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2022-2024 HiSilicon Limited. */
#ifndef __SEC_MAIN_H
#define __SEC_MAIN_H

#include "hisi_qm.h"

#ifdef CFG_HISILICON_ACC_V3
#define SEC_BAR			0x160000000
#else
#define SEC_BAR			0x141800000
#endif
#define SEC_SIZE		0x400000

#define SEC_SQE_SIZE		128
#define SEC_SQE_LOG2_SIZE	7
#define AES_KEYSIZE_128		16
#define AES_KEYSIZE_192		24
#define AES_KEYSIZE_256		32
#define SEC_HW_TASK_DONE	0x1
#define SEC_DONE_MASK		0x0001
#define SEC_ICV_MASK		0x000E
#define SEC_HW_ICV_ERR		0x2
#define SEC_ENCODE_BYTES	4
#define BYTE_BITS		0x8

#define SEC_SCENE_OFFSET	3
#define SEC_DE_OFFSET		1
#define SEC_CIPHER_OFFSET	4
#define SEC_AUTH_OFFSET		6
#define SEC_CMODE_OFFSET	12
#define SEC_CKEY_OFFSET		9
#define SEC_AKEY_OFFSET		5
#define SEC_AEAD_ALG_OFFSET	11
#define SEC_HUK_OFFSET		4
#define SEC_APAD_OFFSET		2

#define SEC_DE_OFFSET_V3	9
#define SEC_SCENE_OFFSET_V3	5
#define SEC_CKEY_OFFSET_V3	13
#define SEC_CALG_OFFSET_V3	4
#define SEC_AKEY_OFFSET_V3	9
#define SEC_MAC_OFFSET_V3	4
#define SEC_AUTH_ALG_OFFSET_V3	15
#define SEC_CIPHER_AUTH_V3	0xbf
#define SEC_AUTH_CIPHER_V3	0x40
#define SEC_AI_GEN_OFFSET_V3	2
#define SEC_SEQ_OFFSET_V3	6
#define SEC_ICV_LEN_OFFSET_V3	4
#define SEC_DK_LEN_OFFSET_V3	16
#define SEC_KEY_SEL_OFFSET_V3	21
#define SEC_GET_FIELD(val, mask, shift) (((val) & (mask)) >> (shift))

struct hisi_sec_sqe_type2 {
	/*
	 * mac_len: 0~4 bits
	 * a_key_len: 5~10 bits
	 * a_alg: 11~16 bits
	 */
	uint32_t mac_key_alg;

	/*
	 * c_icv_len: 0~5 bits
	 * c_width: 6~8 bits
	 * c_key_len: 9~11 bits
	 * c_mode: 12~15 bits
	 */
	uint16_t icvw_kmode;

	/* c_alg: 0~3 bits */
	uint8_t c_alg;

	uint8_t rsvd4;
	/*
	 * a_len: 0~23 bits
	 * iv_offset_l: 24~31 bits
	 */
	uint32_t alen_ivllen;

	/*
	 * c_len: 0~23 bits
	 * iv_offset_h: 24~31 bits
	 */
	uint32_t clen_ivhlen;

	uint16_t auth_src_offset;
	uint16_t cipher_src_offset;
	uint16_t cs_ip_header_offset;
	uint16_t cs_udp_header_offset;
	uint16_t pass_word_len;
	uint16_t dk_len;
	uint8_t salt3;
	uint8_t salt2;
	uint8_t salt1;
	uint8_t salt0;

	uint16_t tag;
	uint16_t rsvd5;

	/*
	 * c_pad_type: 0~3 bits
	 * c_pad_len: 4~11 bits
	 * c_pad_data_type: 12~15 bits
	 */
	uint16_t cph_pad;
	/* c_pad_len_field: 0~1 bits */
	uint16_t c_pad_len_field;

	uint64_t long_a_data_len;
	uint64_t a_ivin_addr;
	uint64_t a_key_addr;
	uint64_t mac_addr;
	uint64_t c_ivin_addr;
	uint64_t c_key_addr;
	uint64_t data_src_addr;
	uint64_t data_dst_addr;

	/*
	 * done: 0 bit
	 * icv: 1~3 bits
	 * csc: 4~6 bits
	 * flag: 7~10 bits
	 */
	uint16_t done_flag;

	uint8_t error_type;
	uint8_t warning_type;
	uint8_t mac_i3;
	uint8_t mac_i2;
	uint8_t mac_i1;
	uint8_t mac_i0;
	uint16_t check_sum_i;
	uint8_t tls_pad_len_i;
	uint8_t rsvd12;
	uint32_t counter;
};

struct hisi_sec_sqe {
	/*
	 * type:  0~3 bits;
	 * cipher: 4~5 bits;
	 * auth: 6~7 bits;
	 */
	uint8_t type_auth_cipher;
	/*
	 * seq: 0 bits;
	 * de: 1~2 bits;
	 * scene: 3~6 bits;
	 * src_addr_type: 7 bits;
	 */
	uint8_t sds_sa_type;
	/*
	 * src_addr_type: 0~1 bits not used now.
	 * dst_addr_type: 2~4 bits;
	 * mac_addr_type: 5~7 bits;
	 */
	uint8_t sdm_addr_type;

	uint8_t rsvd0;
	/*
	 * nonce_len(type): 0~3 bits;
	 * huk: 4 bit;
	 * key_s: 5 bit
	 * ci_gen: 6~7 bits
	 */
	uint8_t huk_ci_key;
	/*
	 * ai_gen: 0~1 bits;
	 * a_pad : 2~3 bits;
	 * c_s : 4~5 bits;
	 */
	uint8_t ai_apd_cs;
	/*
	 * rhf(type2): 0 bit;
	 * c_key_type: 1~2 bits;
	 * a_key_type: 3~4 bits
	 * write_frame_len(type2): 5~7bits;
	 */
	uint8_t rca_key_frm;

	uint8_t iv_tls_ld;
	struct hisi_sec_sqe_type2 type2; /* the other scene */
};

struct bd3_stream_scene {
	uint64_t c_ivin_addr;
	uint64_t long_a_data_len;

	/*
	 * auth_pad: 0~1 bits
	 * stream_protocol: 2~4 bits
	 * reserved: 5~7 bits
	 */
	uint8_t auth_pad;
	uint8_t plaintext_type;
	uint16_t pad_len_1p3;
} __packed __aligned(4);

struct bd3_no_scene {
	uint64_t c_ivin_addr;
	uint32_t rsvd0;
	uint32_t rsvd1;
	uint32_t rsvd2;
} __packed __aligned(4);

struct bd3_pbkdf2_scene {
	uint64_t c_ivin_addr;

	/*
	 * pbkdf2_salt_len: 0~23 bits
	 * rsvd0: 24~31 bits
	 */
	uint32_t pbkdf2_salt_len;

	/*
	 * c_num: 0~23 bits
	 * rsvd1: 24~31 bits
	 */
	uint32_t c_num;

	/*
	 * pass_word_len: 0~15 bits
	 * dk_len: 16~31 bits
	 */
	uint32_t pass_word_dk_len;
} __packed __aligned(4);

struct hisi_sec_bd3_sqe {
	/*
	 * type: 0~3 bit
	 * bd_invalid: 4 bit
	 * scene: 5~8 bit
	 * de: 9~10 bit
	 * src_addr_type: 11~13 bit
	 * dst_addr_type: 14~16 bit
	 * mac_addr_type: 17~19 bit
	 * reserved: 20~31 bits
	 */
	uint32_t bd_param;

	/*
	 * cipher: 0~1 bits
	 * ci_gen: 2~3 bit
	 * c_icv_len: 4~9 bit
	 * c_width: 10~12 bits
	 * c_key_len: 13~15 bits
	 */
	uint16_t c_icv_key;

	/*
	 * c_mode : 0~3 bits
	 * c_alg : 4~7 bits
	 */
	uint8_t c_mode_alg;

	/*
	 * nonce_len : 0~3 bits
	 * huk : 4 bits
	 * cal_iv_addr_en : 5 bits
	 * seq : 6 bits
	 * reserved : 7 bits
	 */
	uint8_t huk_iv_seq;

	uint64_t tag;
	uint64_t data_src_addr;
	uint64_t a_key_addr;
	uint64_t a_ivin_addr;
	uint64_t rsvd;
	uint64_t c_key_addr;

	/*
	 * auth: 0~1 bits
	 * ai_gen: 2~3 bits
	 * mac_len: 4~8 bits
	 * akey_len: 9~14 bits
	 * a_alg: 15~20 bits
	 * key_sel: 21~24 bits
	 * ctr_count_mode/sm4_xts: 25~26 bits
	 * sva_prefetch: 27 bits
	 * key_wrap_num:28~30 bits
	 * update_key: 31 bits
	 */
	uint32_t auth_mac_key;
	uint32_t salt;
	uint16_t auth_src_offset;
	uint16_t cipher_src_offset;

	/*
	 * auth_len: 0~23 bit
	 * auth_key_offset: 24~31 bits
	 */
	uint32_t a_len_key;

	/*
	 * cipher_len: 0~23 bit
	 * auth_ivin_offset: 24~31 bits
	 */
	uint32_t c_len_ivin;
	uint64_t data_dst_addr;
	uint64_t mac_addr;
	union {
		struct bd3_stream_scene stream_scene;
		struct bd3_no_scene no_scene;
		struct bd3_pbkdf2_scene pbkdf2_scene;
	};

	/*
	 * done: 0 bit
	 * icv: 1~3 bit
	 * csc: 4~6 bit
	 * flag: 7~10 bit
	 * reserved: 11~15 bit
	 */
	uint16_t done_flag;
	uint8_t error_type;
	uint8_t warning_type;
	uint64_t kek_key_addr;
	uint32_t counter;
} __packed __aligned(4);

enum sec_bd_type {
	BD_TYPE1 = 0x1,
	BD_TYPE2 = 0x2,
	BD_TYPE3 = 0x3,
};

enum sec_bd_scene {
	SCENE_NOTHING = 0x0,
	SCENE_STREAM = 0x7,
	SCENE_PBKDF2 = 0x8,
};

enum sec_auth_dir {
	NO_AUTH,
	AUTH_MAC_CALCULATE,
	AUTH_MAC_VERIFY,
};

enum sec_bd_seq {
	DATA_DST_ADDR_DISABLE,
	DATA_DST_ADDR_ENABLE,
};

/*
 * Create task queue pair for SEC.
 *
 * @sq_type Task type of the submmission queue.
 */
struct hisi_qp *sec_create_qp(uint8_t sq_type);

#endif
