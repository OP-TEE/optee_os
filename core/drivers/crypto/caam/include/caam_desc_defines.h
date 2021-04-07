/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2018-2021 NXP
 *
 * Brief   CAAM Descriptor defines.
 */
#ifndef __CAAM_DESC_DEFINES_H__
#define __CAAM_DESC_DEFINES_H__

#include <util.h>

/*
 * Common Command constants
 */
#define CMD_TYPE(cmd)		SHIFT_U32((cmd) & 0x1F, 27)
#define GET_CMD_TYPE(op)	((op) & (SHIFT_U32(0x1F, 27)))
#define CMD_CLASS(val)		SHIFT_U32((val) & 0x3, 25)
#define CLASS_NO		0x0
#define CLASS_1			0x1
#define CLASS_2			0x2
#define CLASS_DECO		0x3

#define CMD_SGT			BIT32(24)
#define CMD_IMM			BIT32(23)

/*
 * HEADER Job Descriptor Header format
 */
#define CMD_HDR_JD_TYPE		CMD_TYPE(0x16)

/* Must be ONE */
#define HDR_JD_ONE		BIT32(23)

/* Start Index if SHR = 0 */
#define HDR_JD_START_IDX(line)	SHIFT_U32((line) & 0x3F, 16)

/* Descriptor Length */
#define HDR_JD_DESCLEN(len)	SHIFT_U32((len) & 0x7F, 0)
#define GET_JD_DESCLEN(entry)	((entry) & 0x7F)

/*
 * KEY Command fields
 */
#define CMD_KEY_TYPE		CMD_TYPE(0x00)

/* Key Destination */
#define KEY_DEST(val)		SHIFT_U32((KEY_DEST_##val) & 0x3, 16)
#define KEY_DEST_REG		0x0
#define KEY_DEST_PKHA_E		0x1
#define KEY_DEST_AFHA_SBOX	0x2
#define KEY_DEST_MDHA_SPLIT	0x3

/* Plaintext Store */
#define KEY_PTS			BIT32(14)

/* Key Length */
#define KEY_LENGTH(len)		SHIFT_U32((len) & 0x3FF, 0)

/*
 * LOAD Command fields
 */
#define CMD_LOAD_TYPE		CMD_TYPE(0x02)

/* Load Destination */
#define LOAD_DST(reg)		SHIFT_U32((reg) & 0x7F, 16)

/* Offset in destination register */
#define LOAD_OFFSET(off)	SHIFT_U32((off) & 0xFF, 8)

/* Length */
#define LOAD_LENGTH(len)	SHIFT_U32((len) & 0xFF, 0)

/*
 * STORE Command fields
 */
#define CMD_STORE_TYPE		CMD_TYPE(0x0A)
#define CMD_STORE_SEQ_TYPE	CMD_TYPE(0x0B)

/* Store Source */
#define STORE_SRC(reg)		SHIFT_U32((reg) & 0x7F, 16)

/* Offset in source register */
#define STORE_OFFSET(off)	SHIFT_U32((off) & 0xFF, 8)

/* Length */
#define STORE_LENGTH(len)	SHIFT_U32((len) & 0xFF, 0)

/*
 * Define the Load/Store Registers Source and Destination
 */
#define REG_MODE			0x00
#define REG_KEY_SIZE			0x01
#define REG_DATA_SIZE			0x02
#define REG_ICV_SIZE			0x03
#define REG_DECO_MID_STATUS		0x04
#define REG_DECO_CTRL2			0x05
#define REG_CHA_CTRL			0x06
#define REG_DECO_CTRL			0x06
#define REG_IRQ_CTRL			0x07
#define REG_DECO_PROT_OVERWRITE		0x07
#define REG_CLEAR_WRITTEN		0x08
#define REG_MATH0			0x08
#define REG_MATH1			0x09
#define REG_MATH2			0x0A
#define REG_CHA_INST_SELECT		0x0A
#define REG_AAD_SIZE			0x0B
#define REG_MATH3			0x0B
#define REG_ALT_DATA_SIZE_C1		0x0F
#define REG_PKHA_A_SIZE			0x10
#define REG_PKHA_B_SIZE			0x11
#define REG_PKHA_N_SIZE			0x12
#define REG_PKHA_E_SIZE			0x13
#define REG_CTX				0x20
#define REG_MATH0_DW			0x30
#define REG_MATH1_DW			0x31
#define REG_MATH2_DW			0x32
#define REG_MATH3_DW			0x33
#define REG_MATH0_B			0x38
#define REG_MATH1_B			0x39
#define REG_MATH2_B			0x3A
#define REG_MATH3_B			0x3B
#define REG_KEY				0x40
#define REG_DECO_DESC			0x40
#define REG_NFIFO_n_SIZE		0x70
#define REG_NFIFO_MATH			0x73
#define REG_SIZE			0x74
#define REG_SIZE_MATH			0x75
#define REG_IFIFO_SHIFT			0x76
#define REG_OFIFO_SHIFT			0x77
#define REG_AUX_FIFO			0x78
#define REG_NFIFO			0x7A
#define REG_IFIFO			0x7C
#define REG_OFIFO			0x7E

/*
 * FIFO LOAD Command fields
 */
#define CMD_FIFO_LOAD_TYPE	CMD_TYPE(0x04)

/* Extended Length */
#define FIFO_LOAD_EXT		BIT32(22)

/* Input data */
#define FIFO_LOAD_INPUT(reg)	SHIFT_U32((FIFO_LOAD_##reg) & 0x3F, 16)
#define FIFO_LOAD_ACTION(act)	SHIFT_U32((FIFO_LOAD_##act) & 0x3F, 16)

/* Length */
#define FIFO_LOAD_MAX		0xFFFF
#define FIFO_LOAD_LENGTH(len)	SHIFT_U32((len) & FIFO_LOAD_MAX, 0)

/*
 * Define the FIFO Load Type Input
 */
#define FIFO_LOAD_PKHA_A0		0x00
#define FIFO_LOAD_PKHA_A1		0x01
#define FIFO_LOAD_PKHA_A2		0x02
#define FIFO_LOAD_PKHA_A3		0x03
#define FIFO_LOAD_PKHA_B0		0x04
#define FIFO_LOAD_PKHA_B1		0x05
#define FIFO_LOAD_PKHA_B2		0x06
#define FIFO_LOAD_PKHA_B3		0x07
#define FIFO_LOAD_PKHA_N		0x08
#define FIFO_LOAD_PKHA_A		0x0C
#define FIFO_LOAD_PKHA_B		0x0D
#define FIFO_LOAD_NO_INFO_NFIFO		0x0F
#define FIFO_LOAD_MSG			0x10
#define FIFO_LOAD_MSG_C1_OUT_C2		0x18
#define FIFO_LOAD_IV			0x20
#define FIFO_LOAD_BITDATA		0x2C
#define FIFO_LOAD_AAD			0x30
#define FIFO_LOAD_ICV			0x38

/* Define Action of some FIFO Data */
#define FIFO_LOAD_NOACTION		0x0
#define FIFO_LOAD_FLUSH			0x1
#define FIFO_LOAD_LAST_C1		0x2
#define FIFO_LOAD_LAST_C2		0x4

/*
 * FIFO STORE Command fields
 */
#define CMD_FIFO_STORE_TYPE	CMD_TYPE(0x0C)
#define CMD_SEQ_FIFO_STORE_TYPE CMD_TYPE(0x0D)

/* Extended Length */
#define FIFO_STORE_EXT		BIT32(22)

/* Output data */
#define FIFO_STORE_OUTPUT(reg)	SHIFT_U32((FIFO_STORE_##reg) & 0x3F, 16)

/* Length */
#define FIFO_STORE_MAX		0xFFFF
#define FIFO_STORE_LENGTH(len)	SHIFT_U32((len) & FIFO_STORE_MAX, 0)

/*
 * Define the FIFO Store Type Output
 */
#define FIFO_STORE_PKHA_A0                           0x00
#define FIFO_STORE_PKHA_A1                           0x01
#define FIFO_STORE_PKHA_A2                           0x02
#define FIFO_STORE_PKHA_A3                           0x03
#define FIFO_STORE_PKHA_B0                           0x04
#define FIFO_STORE_PKHA_B1                           0x05
#define FIFO_STORE_PKHA_B2                           0x06
#define FIFO_STORE_PKHA_B3                           0x07
#define FIFO_STORE_PKHA_N                            0x08
#define FIFO_STORE_PKHA_A                            0x0C
#define FIFO_STORE_PKHA_B                            0x0D
#define FIFO_STORE_AFHA_SBOX_AES_CCM_JKEK            0x10
#define FIFO_STORE_AFHA_SBOX_AES_CCM_TKEK            0x11
#define FIFO_STORE_PKHA_E_AES_CCM_JKEK               0x12
#define FIFO_STORE_PKHA_E_AES_CCM_TKEK               0x13
#define FIFO_STORE_KEY_AES_CCM_JKEK                  0x14
#define FIFO_STORE_KEY_AES_CCM_TKEK                  0x15
#define FIFO_STORE_C2_MDHA_SPLIT_KEY_AES_CCM_JKEK    0x16
#define FIFO_STORE_C2_MDHA_SPLIT_KEY_AES_CCM_TKEK    0x17
#define FIFO_STORE_AFHA_SBOX_AES_ECB_JKEK            0x20
#define FIFO_STORE_AFHA_SBOX_AES_ECB_TKEK            0x21
#define FIFO_STORE_PKHA_E_AES_ECB_JKEK               0x22
#define FIFO_STORE_PKHA_E_AES_ECB_TKEK               0x23
#define FIFO_STORE_KEY_AES_ECB_JKEK                  0x24
#define FIFO_STORE_KEY_AES_ECB_TKEK                  0x25
#define FIFO_STORE_C2_MDHA_SPLIT_KEY_AES_ECB_JKEK    0x26
#define FIFO_STORE_C2_MDHA_SPLIT_KEY_AES_ECB_TKEK    0x27
#define FIFO_STORE_MSG_DATA                          0x30
#define FIFO_STORE_RNG_TO_MEM                        0x34
#define FIFO_STORE_RNG_STAY_FIFO                     0x35
#define FIFO_STORE_SKIP                              0x3F

/*
 * MOVE Command fields
 */
#define CMD_MOVE_TYPE		CMD_TYPE(0x0F)

/* Auxiliary */
#define MOVE_AUX(val)		SHIFT_U32((val) & 0x3, 25)

/* Wait for completion */
#define MOVE_WC			BIT32(24)

/* Source */
#define MOVE_SRC(src)			MOVE_SRC_##src
#define MOVE_REG_SRC(reg)		SHIFT_U32((reg) & 0xF, 20)
#define MOVE_SRC_C1_CTX_REG		MOVE_REG_SRC(0x0)
#define MOVE_SRC_C2_CTX_REG		MOVE_REG_SRC(0x1)
#define MOVE_SRC_OFIFO			MOVE_REG_SRC(0x2)
#define MOVE_SRC_DESC_BUF		MOVE_REG_SRC(0x3)
#define MOVE_SRC_MATH_REG0		MOVE_REG_SRC(0x4)
#define MOVE_SRC_MATH_REG1		MOVE_REG_SRC(0x5)
#define MOVE_SRC_MATH_REG2		MOVE_REG_SRC(0x6)
#define MOVE_SRC_MATH_REG3		MOVE_REG_SRC(0x7)
#define MOVE_SRC_NFIFO_DECO_ALIGN	MOVE_REG_SRC(0x8)
#define MOVE_SRC_NFIFO_C1_ALIGN		(MOVE_REG_SRC(0x9) | MOVE_AUX(0x1))
#define MOVE_SRC_NFIFO_C2_ALIGN		(MOVE_REG_SRC(0x9) | MOVE_AUX(0x0))
#define MOVE_SRC_DECO_ALIGN		(MOVE_REG_SRC(0xA) | MOVE_AUX(0x0))
#define MOVE_SRC_C1_ALIGN		(MOVE_REG_SRC(0xA) | MOVE_AUX(0x1))
#define MOVE_SRC_C2_ALIGN		(MOVE_REG_SRC(0xA) | MOVE_AUX(0x2))
#define MOVE_SRC_C1_KEY			MOVE_REG_SRC(0xD)
#define MOVE_SRC_C2_KEY			MOVE_REG_SRC(0xE)

/* Destination */
#define MOVE_DST(dst)			SHIFT_U32((MOVE_DST_##dst), 16)
#define MOVE_DST_C1_CTX_REG		0x0
#define MOVE_DST_C2_CTX_REG		0x1
#define MOVE_DST_OFIFO			0x2
#define MOVE_DST_DESC_BUF		0x3
#define MOVE_DST_MATH_REG0		0x4
#define MOVE_DST_MATH_REG1		0x5
#define MOVE_DST_MATH_REG2		0x6
#define MOVE_DST_MATH_REG3		0x7
#define MOVE_DST_IFIFO_C1		0x8
#define MOVE_DST_IFIFO_C2		0x9
#define MOVE_DST_IFIFO_C2_LC2		((0x9 << 16 | MOVE_AUX(0x1)) >> 16)
#define MOVE_DST_IFIFO			0xA
#define MOVE_DST_PKHA_A			0xC
#define MOVE_DST_C1_KEY			0xD
#define MOVE_DST_C2_KEY			0xE
#define MOVE_DST_AUX_FIFO		0xF

/* Offset */
#define MOVE_OFFSET(off)	SHIFT_U32((off) & 0xFF, 8)

/* Length */
#define MOVE_LENGTH(len)	SHIFT_U32((len) & 0xFF, 0)

/*
 * Operation Command fields
 * Algorithm/Protocol/PKHA
 */
#define CMD_OP_TYPE		CMD_TYPE(0x10)

/* Operation Type */
#define OP_TYPE(type) SHIFT_U32((OP_TYPE_##type) & 0x7, 24)
#define OP_TYPE_UNI		0x0
#define OP_TYPE_PKHA		0x1
#define OP_TYPE_CLASS1		0x2
#define OP_TYPE_CLASS2		0x4
#define OP_TYPE_DECAPS		0x6
#define OP_TYPE_ENCAPS		0x7

/* Protocol Identifier */
#define PROTID(id)		SHIFT_U32((PROTID_##id) & 0xFF, 16)
#define PROTID_BLOB		0x0D
#define PROTID_MPKEY		0x14
#define PROTID_PKKEY		0x14
#define PROTID_MPSIGN		0x15
#define PROTID_DSASIGN		0x15
#define PROTID_DSAVERIFY	0x16
#define PROTID_SHARED_SECRET	0x17
#define PROTID_RSA_ENC		0x18
#define PROTID_RSA_DEC		0x19
#define PROTID_RSA_FINISH_KEY	0x1A

/*
 * RSA Protocol Information
 */
#define PROT_RSA_FMT(format)	SHIFT_U32((PROT_RSA_FMT_##format) & 0x1, 12)
#define PROT_RSA_FMT_NO		0
#define PROT_RSA_FMT_PKCS_V1_5	1

#define PROT_RSA_DEC_KEYFORM(format)	SHIFT_U32(((format) - 1) & 0x3, 0)

/* RSA Key Protocol Information */
#define PROT_RSA_KEY(format)	SHIFT_U32((PROT_RSA_KEY_##format) & 0x3, 0)
#define PROT_RSA_KEY_ALL	0
#define PROT_RSA_KEY_N_D	2

/*
 * ECC Protocol Information
 */
#define PROT_PK_MSG(type)	SHIFT_U32(PROT_PK_MSG_##type, 10)
#define PROT_PK_MSG_HASHED	2
#define PROT_PK_TYPE(type)	SHIFT_U32(PROT_PK_##type, 1)
#define PROT_PK_DL		0
#define PROT_PK_ECC		1

/*
 * BLOB Protocol Information
 */
#define PROT_BLOB_FMT_MSTR		BIT32(1)
#define PROT_BLOB_TYPE(type)		SHIFT_U32(1, PROT_BLOB_TYPE_##type)
#define PROT_BLOB_TYPE_BLACK_KEY	2
#define PROT_BLOB_EKT			8
#define PROT_BLOB_INFO(aes)		SHIFT_U32(PROT_BLOB_AES_##aes, \
						PROT_BLOB_EKT)
#define PROT_BLOB_AES_CCM		1
#define PROT_BLOB_AES_ECB		0
#define PROT_BLOB_FORMAT(format)	SHIFT_U32(0, PROT_BLOB_FORMAT_##format)
#define PROT_BLOB_FORMAT_NORMAL		0

/*
 * Algorithm Identifier
 */
#define OP_ALGO(algo)		SHIFT_U32((ALGO_##algo) & 0xFF, 16)
#define ALGO_AES		0x10
#define ALGO_DES		0x20
#define ALGO_3DES		0x21
#define ALGO_ARC4		0x30
#define ALGO_RNG		0x50
#define ALGO_MD5		0x40
#define ALGO_SHA1		0x41
#define ALGO_SHA224		0x42
#define ALGO_SHA256		0x43
#define ALGO_SHA384		0x44
#define ALGO_SHA512		0x45
#define ALGO_SHA512_224		0x46
#define ALGO_SHA512_256		0x47

/* Algorithm Additional Information */
#define ALGO_AAI(info)		SHIFT_U32((AAI_##info) & 0x1FF, 4)

/* AES AAI */
#define AAI_AES_CTR_MOD128	0x00
#define AAI_AES_CBC		0x10
#define AAI_AES_ECB		0x20
#define AAI_AES_CFB		0x30
#define AAI_AES_OFB		0x40
#define AAI_AES_CMAC		0x60
#define AAI_AES_XCBC_MAC	0x70
#define AAI_AES_CCM		0x80
#define AAI_AES_GCM		0x90

/* DES AAI */
#define AAI_DES_CBC		0x10
#define AAI_DES_ECB		0x20
#define AAI_DES_CFB		0x30
#define AAI_DES_OFB		0x40

/* Digest MD5/SHA AAI */
#define AAI_DIGEST_HASH		0x00
#define AAI_DIGEST_HMAC		0x01
#define AAI_DIGEST_SMAC		0x02
#define AAI_DIGEST_HMAC_PRECOMP	0x04

/* Algorithm State */
#define ALGO_AS(state)		SHIFT_U32((AS_##state) & 0x3, 2)
#define AS_UPDATE		0x0
#define AS_INIT			0x1
#define AS_FINAL		0x2
#define AS_INIT_FINAL		0x3

/* Algorithm Encrypt/Decrypt */
#define ALGO_DECRYPT		SHIFT_U32(0x0, 0)
#define ALGO_ENCRYPT		SHIFT_U32(0x1, 0)

/*
 * Specific RNG Algorithm bits 12-0
 */
/* Secure Key */
#define ALGO_RNG_SK		BIT32(12)

/* State Handle */
#define ALGO_RNG_SH(sh)		SHIFT_U32((sh) & 0x3, 4)

/* State */
#define AS_RNG_GENERATE		0x0
#define AS_RNG_INSTANTIATE	0x1
#define AS_RNG_RESEED		0x2
#define AS_RNG_UNINSTANTIATE	0x3

/*
 * JUMP Command fields
 */
#define CMD_JUMP_TYPE		CMD_TYPE(0x14)

/* Jump Select Type */
#define JMP_JSL			BIT32(24)

/* Jump Type */
#define JUMP_TYPE(type)		SHIFT_U32((JMP_##type) & 0xF, 20)
#define JMP_LOCAL		0x0
#define JMP_LOCAL_INC		0x1
#define JMP_SUBROUTINE_CALL	0x2
#define JMP_LOCAL_DEC		0x3
#define JMP_NON_LOCAL		0x4
#define JMP_SUBROUTINE_RET	0x6
#define JMP_HALT		0x8
#define JMP_HALT_USER_STATUS	0xC

/* Test Type */
#define JUMP_TST_TYPE(type)	SHIFT_U32((JMP_TST_##type) & 0x3, 16)
#define JMP_TST_ALL_COND_TRUE	0x0
#define JMP_TST_ALL_COND_FALSE	0x1
#define JMP_TST_ANY_COND_TRUE	0x2
#define JMP_TST_ANY_COND_FALSE	0x3

/* Jump Source to increment/decrement */
#define JMP_SRC(src)	SHIFT_U32((JMP_SRC_##src) & 0xF, 12)
#define JMP_SRC_MATH_0	0x0

/* Test Condition */
#define JMP_COND(cond)		SHIFT_U32((JMP_COND_##cond) & 0xFF, 8)
#define JMP_COND_MATH(cond)	SHIFT_U32((JMP_COND_MATH_##cond) & 0xF, 8)
#define JMP_COND_NONE		0x00
#define JMP_COND_PKHA_IS_ZERO	0x80
#define JMP_COND_PKHA_GCD_1	0x40
#define JMP_COND_PKHA_IS_PRIME	0x20
#define JMP_COND_MATH_N		0x08
#define JMP_COND_MATH_Z		0x04
#define JMP_COND_NIFP		0x04
#define JMP_COND_MATH_C		0x02
#define JMP_COND_MATH_NV	0x01

/* Local Offset */
#define JMP_LOCAL_OFFSET(off)	SHIFT_U32((off) & 0xFF, 0)

/*
 * MATH Command fields
 */
#define CMD_MATH_TYPE		CMD_TYPE(0x15)
#define CMD_MATHI_TYPE		CMD_TYPE(0x1D)

/* Immediate Four Bytes */
#define MATH_IFB		BIT32(26)

/* Function Mathematical */
#define MATH_FUNC(func)		SHIFT_U32((MATH_FUNC_##func) & 0xF, 20)
#define MATH_FUNC_ADD		0x0
#define MATH_FUNC_ADD_W_CARRY	0x1
#define MATH_FUNC_SUB		0x2
#define MATH_FUNC_SUB_W_BORROW	0x3
#define MATH_FUNC_OR		0x4
#define MATH_FUNC_AND		0x5
#define MATH_FUNC_XOR		0x6
#define MATH_FUNC_SHIFT_L	0x7
#define MATH_FUNC_SHIFT_R	0x8
#define MATH_FUNC_SHLD		0x9
#define MATH_FUNC_ZBYTE		0xA
#define MATH_FUNC_SWAP_BYTES	0xB

/* Source 0 */
#define MATH_SRC0(reg)		SHIFT_U32((MATH_SRC0_##reg) & 0xF, 16)
#define MATH_SRC0_REG0		0x0
#define MATH_SRC0_REG1		0x1
#define MATH_SRC0_REG2		0x2
#define MATH_SRC0_IMM_DATA	0x4
#define MATH_SRC0_DPOVRD	0x7
#define MATH_SRC0_SIL		0x8
#define MATH_SRC0_SOL		0x9
#define MATH_SRC0_VSIL		0xA
#define MATH_SRC0_VSOL		0xB
#define MATH_SRC0_ZERO		0xC
#define MATH_SRC0_ONE		0xF

/* Source 1 */
#define MATH_SRC1(reg)		SHIFT_U32((MATH_SRC1_##reg) & 0xF, 12)
#define MATH_SRC1_REG0		0x0
#define MATH_SRC1_REG1		0x1
#define MATH_SRC1_REG2		0x2
#define MATH_SRC1_IMM_DATA	0x4
#define MATH_SRC1_DPOVRD	0x7
#define MATH_SRC1_VSIL		0x8
#define MATH_SRC1_VSOL		0x9
#define MATH_SRC1_IFIFO		0xA
#define MATH_SRC1_OFIFO		0xB
#define MATH_SRC1_ONE		0xC
#define MATH_SRC1_ZERO		0xF

/* Destination */
#define MATH_DST(reg)		SHIFT_U32((MATH_DST_##reg) & 0xF, 8)
#define MATH_DST_REG0		0x0
#define MATH_DST_REG1		0x1
#define MATH_DST_REG2		0x2
#define MATH_DST_DPOVRD		0x7
#define MATH_DST_SIL		0x8
#define MATH_DST_SOL		0x9
#define MATH_DST_VSIL		0xA
#define MATH_DST_VSOL		0xB
#define MATH_DST_NODEST		0xF

/* Length */
#define MATH_LENGTH(len)	SHIFT_U32((len) & 0xF, 0)

/* Immediate Value - MATHI operation */
#define MATHI_SRC(reg)		SHIFT_U32((MATH_SRC0_##reg) & 0xF, 16)
#define MATHI_DST(reg)		SHIFT_U32((MATH_DST_##reg) & 0xF, 12)
#define MATHI_IMM_VALUE(val)	SHIFT_U32((val) & 0xFF, 4)

/*
 * Sequence Input/Output
 */
#define CMD_SEQ_IN_TYPE		CMD_TYPE(0x1E)
#define CMD_SEQ_OUT_TYPE	CMD_TYPE(0x1F)

/* Extended Length */
#define SEQ_EXT BIT(22)

/* Length */
#define SEQ_LENGTH(len)		SHIFT_U32((len) & 0xFFFF, 0)

/*
 * PKHA Operation
 */
#define PKHA_ALG		SHIFT_U32(0x8, 20)

#define PKHA_F2M		BIT32(17)

#define PKHA_OUTSEL(dst)	SHIFT_U32((PKHA_OUTSEL_##dst) & 0x3, 8)
#define PKHA_OUTSEL_B		0x0
#define PKHA_OUTSEL_A		0x1

#define PKHA_FUNC(func)		SHIFT_U32((PKHA_FUNC_##func) & 0x3F, 0)
#define PKHA_FUNC_CPY_NSIZE		0x10
#define PKHA_FUNC_CPY_SSIZE		0x11
#define PKHA_FUNC_MOD_ADD_A_B		0x02
#define PKHA_FUNC_MOD_SUB_A_B		0x03
#define PKHA_FUNC_MOD_SUB_B_A		0x04
#define PKHA_FUNC_MOD_MUL_A_B		0x05
#define PKHA_FUNC_MOD_EXP_A_E		0x06
#define PKHA_FUNC_MOD_AMODN		0x07
#define PKHA_FUNC_MOD_INV_A		0x08
#define PKHA_FUNC_ECC_POINT_ADD_P1_P2	0x09
#define PKHA_FUNC_ECC_POINT_DBL_P1	0x0A
#define PKHA_FUNC_ECC_POINT_MUL_E_P1	0x0B
#define PKHA_FUNC_MONT_RADIX_R2_MODE_N	0x0C
#define PKHA_FUNC_GCD_A_N		0x0E
#define PKHA_FUNC_MR_PRIMER_TEST	0x0F
#define PKHA_FUNC_MOD_CHECK_POINT	0x1C

/* PKHA Copy Memory Source and Destination */
#define PKHA_REG_SRC(reg)	SHIFT_U32((PKHA_REG_##reg) & 0x7, 17)
#define PKHA_REG_DST(reg)	SHIFT_U32((PKHA_REG_##reg) & 0x3, 10)
#define PKHA_REG_A		0x0
#define PKHA_REG_B		0x1
#define PKHA_REG_E		0x2
#define PKHA_REG_N		0x3

#define PKHA_SEG_SRC(seg)	SHIFT_U32((seg) & 0x3, 8)
#define PKHA_SEG_DST(seg)	SHIFT_U32((seg) & 0x3, 6)

#define PKHA_CPY_SRC(src)	PKHA_CPY_SRC_##src
#define PKHA_CPY_SRC_A0		(PKHA_REG_SRC(A) | PKHA_SEG_SRC(0))
#define PKHA_CPY_SRC_A1		(PKHA_REG_SRC(A) | PKHA_SEG_SRC(1))
#define PKHA_CPY_SRC_A2		(PKHA_REG_SRC(A) | PKHA_SEG_SRC(2))
#define PKHA_CPY_SRC_A3		(PKHA_REG_SRC(A) | PKHA_SEG_SRC(3))
#define PKHA_CPY_SRC_B0		(PKHA_REG_SRC(B) | PKHA_SEG_SRC(0))
#define PKHA_CPY_SRC_B1		(PKHA_REG_SRC(B) | PKHA_SEG_SRC(1))
#define PKHA_CPY_SRC_B2		(PKHA_REG_SRC(B) | PKHA_SEG_SRC(2))
#define PKHA_CPY_SRC_B3		(PKHA_REG_SRC(B) | PKHA_SEG_SRC(3))
#define PKHA_CPY_SRC_N0		(PKHA_REG_SRC(N) | PKHA_SEG_SRC(0))
#define PKHA_CPY_SRC_N1		(PKHA_REG_SRC(N) | PKHA_SEG_SRC(1))
#define PKHA_CPY_SRC_N2		(PKHA_REG_SRC(N) | PKHA_SEG_SRC(2))
#define PKHA_CPY_SRC_N3		(PKHA_REG_SRC(N) | PKHA_SEG_SRC(3))

#define PKHA_CPY_DST(dst)	PKHA_CPY_DST_##dst
#define PKHA_CPY_DST_A0		(PKHA_REG_DST(A) | PKHA_SEG_DST(0))
#define PKHA_CPY_DST_A1		(PKHA_REG_DST(A) | PKHA_SEG_DST(1))
#define PKHA_CPY_DST_A2		(PKHA_REG_DST(A) | PKHA_SEG_DST(2))
#define PKHA_CPY_DST_A3		(PKHA_REG_DST(A) | PKHA_SEG_DST(3))
#define PKHA_CPY_DST_B0		(PKHA_REG_DST(B) | PKHA_SEG_DST(0))
#define PKHA_CPY_DST_B1		(PKHA_REG_DST(B) | PKHA_SEG_DST(1))
#define PKHA_CPY_DST_B2		(PKHA_REG_DST(B) | PKHA_SEG_DST(2))
#define PKHA_CPY_DST_B3		(PKHA_REG_DST(B) | PKHA_SEG_DST(3))
#define PKHA_CPY_DST_N0		(PKHA_REG_DST(N) | PKHA_SEG_DST(0))
#define PKHA_CPY_DST_N1		(PKHA_REG_DST(N) | PKHA_SEG_DST(1))
#define PKHA_CPY_DST_N2		(PKHA_REG_DST(N) | PKHA_SEG_DST(2))
#define PKHA_CPY_DST_N3		(PKHA_REG_DST(N) | PKHA_SEG_DST(3))
#define PKHA_CPY_DST_E		(PKHA_REG_DST(E))

/*
 * Descriptor Protocol Data Block
 */
/* RSA Encryption */
#define PDB_RSA_ENC_SGT_F	SHIFT_U32(1, 31)
#define PDB_RSA_ENC_SGT_G	SHIFT_U32(1, 30)
#define PDB_RSA_ENC_E_SIZE(len)	SHIFT_U32((len) & 0xFFF, 12)
#define PDB_RSA_ENC_N_SIZE(len)	SHIFT_U32((len) & 0xFFF, 0)
#define PDB_RSA_ENC_F_SIZE(len)	SHIFT_U32((len) & 0xFFF, 0)

/* RSA Decryption */
#define PDB_RSA_DEC_SGT_G	SHIFT_U32(1, 31)
#define PDB_RSA_DEC_SGT_F	SHIFT_U32(1, 30)
#define PDB_RSA_DEC_D_SIZE(len)	SHIFT_U32((len) & 0xFFF, 12)
#define PDB_RSA_DEC_N_SIZE(len)	SHIFT_U32((len) & 0xFFF, 0)
#define PDB_RSA_DEC_Q_SIZE(len)	SHIFT_U32((len) & 0xFFF, 12)
#define PDB_RSA_DEC_P_SIZE(len)	SHIFT_U32((len) & 0xFFF, 0)

/* RSA Finalize Key */
#define PDB_RSA_KEY_P_SIZE(len)	SHIFT_U32((len) & 0x1FF, 0)
#define PDB_RSA_KEY_E_SIZE(len)	SHIFT_U32((len) & 0x3FF, 0)
#define PDB_RSA_KEY_N_SIZE(len)	SHIFT_U32((len) & 0x3FF, 16)

/* Manufacturing Curve Select */
#define PDB_MP_CSEL_P256	0x03
#define PDB_MP_CSEL_P384	0x04
#define PDB_MP_CSEL_P521	0x05

/* Public Key Generation */
#define PDB_PKGEN_PD1		SHIFT_U32(1, 25)
/* Public Key Signature */
#define PDB_PKSIGN_PD1		SHIFT_U32(1, 22)
/* Public Key Verify */
#define PDB_PKVERIFY_PD1	SHIFT_U32(1, 22)
/* Shared Secret */
#define PDB_SHARED_SECRET_PD1	SHIFT_U32(1, 25)

/* DSA Signatures */
#define PDB_DSA_SIGN_N(len) SHIFT_U32((len) & (0x7F), 0)
#define PDB_DSA_SIGN_L(len) SHIFT_U32((len) & (0x3FF), 7)

/* SGT Flags Signature */
#define PDB_SGT_PKSIGN_MSG	SHIFT_U32(1, 27)
#define PDB_SGT_PKSIGN_SIGN_C	SHIFT_U32(1, 26)
#define PDB_SGT_PKSIGN_SIGN_D	SHIFT_U32(1, 25)

/* DSA Verify */
#define PDB_DSA_VERIF_N(len) SHIFT_U32((len) & (0x7F), 0)
#define PDB_DSA_VERIF_L(len) SHIFT_U32((len) & (0x3FF), 7)

/* SGT Flags Verify */
#define PDB_SGT_PKVERIF_MSG	SHIFT_U32(1, 27)
#define PDB_SGT_PKVERIF_SIGN_C	SHIFT_U32(1, 26)
#define PDB_SGT_PKVERIF_SIGN_D	SHIFT_U32(1, 25)

/* SGT Flags Shared Secret */
#define PDB_SGT_PKDH_SECRET	SHIFT_U32(1, 27)

/* DL Keypair Generation */
#define PDB_DL_KEY_L_SIZE(len) SHIFT_U32((len) & (0x3FF), 7)
#define PDB_DL_KEY_N_MASK      0x7F
#define PDB_DL_KEY_N_SIZE(len) SHIFT_U32((len) & (PDB_DL_KEY_N_MASK), 0)

/* ECC Domain Selection */
#define PDB_ECC_ECDSEL(curve)	SHIFT_U32((curve) & 0x3F, 7)

/* Black key padding */
#define BLACK_KEY_NONCE_SIZE	6
#define BLACK_KEY_ICV_SIZE	6

/*
 * ECC Predefined Domain
 */
enum caam_ecc_curve {
	CAAM_ECC_P192 = (0x00),
	CAAM_ECC_P224,
	CAAM_ECC_P256,
	CAAM_ECC_P384,
	CAAM_ECC_P521,
	CAAM_ECC_MAX,
	CAAM_ECC_UNKNOWN = (0xFF),
};

#endif /* __CAAM_DESC_DEFINES_H__ */
