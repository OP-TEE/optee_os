/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2022-2024 HiSilicon Limited. */
#ifndef __SEC_MAIN_H
#define __SEC_MAIN_H

#include <hisi_qm.h>

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

/*
 * Create task queue pair for SEC.
 *
 * @sq_type Task type of the submmission queue.
 */
struct hisi_qp *sec_create_qp(uint8_t sq_type);

#endif
