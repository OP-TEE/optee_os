/* SPDX-License-Identifier: BSD-2-Clause */
/**
 * @copyright 2018-2019 NXP
 *
 * @file    desc_interface.h
 *
 * @brief   CAAM Descriptor interface.
 */
#ifndef __DESC_HELPER_H__
#define __DESC_HELPER_H__

/* Global includes */
#include <trace.h>

/* Local includes */
#include "desc_defines.h"

/**
 * @brief   Descriptor Entry type
 */
#ifdef CFG_CAAM_64BITS
typedef uint64_t descEntry_t;
#else
typedef uint32_t descEntry_t;
#endif

/**
 * @brief   Descriptor pointer type
 */
typedef uint32_t *descPointer_t;

/**
 * @brief   Descriptor status type
 */
typedef uint32_t descStatus_t;

/**
 * @brief  Returns the number of entries of the descriptor \a desc
 */
uint32_t desc_get_len(uint32_t *desc);

/* Descriptor Modification function */
void desc_init(uint32_t *desc);
void desc_update_hdr(uint32_t *desc, uint32_t word);
void desc_add_ptr(uint32_t *desc, paddr_t ptr);
void desc_add_word(uint32_t *desc, uint32_t word);

/* Debug print function to dump a Descriptor in hex */
static inline void dump_desc(void *desc)
{
	size_t idx;
	size_t len;
	descPointer_t buf = desc;

	len = desc_get_len(desc);

	for (idx = 0; idx < len; idx++)
		trace_printf(NULL, 0, 0, false, "[%02d] %08X",
				(int)idx, buf[idx]);
}

/**
 * @brief  Returns the descriptor size in bytes of \a nbEntries
 */
#define DESC_SZBYTES(nbEntries)	(nbEntries * sizeof(uint32_t))

/**
 * @brief  Descriptor Header starting at index \a idx w/o descriptor length
 */
#define DESC_HDR(idx) \
			(CMD_HDR_JD_TYPE | HDR_JD_ONE | HDR_JD_START_IDX(idx))

/**
 * @brief  Descriptor Header starting at index 0 with descriptor length \a len
 */
#define DESC_HEADER(len) \
			(DESC_HDR(0) | HDR_JD_DESCLEN(len))

/**
 * @brief  Descriptor Header starting at index \a idx
 *         with descriptor length \a len
 */
#define DESC_HEADER_IDX(len, idx) \
			(DESC_HDR(idx) | HDR_JD_DESCLEN(len))

/**
 * @brief  Jump Local of class \a cla to descriptor offset \a offset
 *          if test \a test meet the condition \a cond
 */
#define JUMP_LOCAL(cla, test, cond, offset) \
		(CMD_JUMP_TYPE | CMD_CLASS(cla) | JUMP_TYPE(LOCAL) | \
		JUMP_TST_TYPE(test) | cond | \
		JMP_LOCAL_OFFSET(offset))

/**
 * @brief  Jump Local of no class to descriptor offset \a offset
 *          if test \a test meet the condition \a cond
 */
#define JUMP_CNO_LOCAL(test, cond, offset) \
			JUMP_LOCAL(CLASS_NO, test, cond, offset)

/**
 * @brief  Jump Local of class 1 to descriptor offset \a offset
 *          if test \a test meet the condition \a cond
 */
#define JUMP_C1_LOCAL(test, cond, offset) \
			JUMP_LOCAL(CLASS_1, test, cond, offset)

/**
 * @brief  Jump No Local of class \a cla to descriptor offset \a offset
 *          if test \a test meet the condition \a cond
 */
#define JUMP_NOTLOCAL(cla, test, cond) \
		(CMD_JUMP_TYPE | CMD_CLASS(cla) | JUMP_TYPE(NON_LOCAL) | \
		JUMP_TST_TYPE(test) | cond)


/**
 * @brief  User Halt with error \a error if test \a test meet
 *         the condition \a cond
 */
#define HALT_USER(test, cond, error) \
		(CMD_JUMP_TYPE | JUMP_TYPE(HALT_USER_STATUS) |	\
		JUMP_TST_TYPE(test) | JMP_COND(cond) | \
		JMP_LOCAL_OFFSET(error))

/**
 * @brief  Load Immediate value of length \a len to register \a dst of
 *         class \a cla
 */
#define LD_IMM(cla, dst, len) \
			(CMD_LOAD_TYPE | CMD_CLASS(cla) | CMD_IMM |	\
			LOAD_DST(dst) | LOAD_LENGTH(len))

/**
 * @brief  Load Immediate value of length \a len to register \a dst w/o class
 */
#define LD_NOCLASS_IMM(dst, len) \
			LD_IMM(CLASS_NO, dst, len)

/**
 * @brief  Load value of length \a len to register \a dst of
 *         class \a cla
 */
#define LD_NOIMM(cla, dst, len) \
			(CMD_LOAD_TYPE | CMD_CLASS(cla) | LOAD_DST(dst) | \
			LOAD_LENGTH(len))

/**
 * @brief  Load value of length \a len to register \a dst of
 *         class \a cla starting of register offset \a off
 */
#define LD_NOIMM_OFF(cla, dst, len, off) \
			(CMD_LOAD_TYPE | CMD_CLASS(cla) | LOAD_DST(dst) | \
			LOAD_OFFSET(off) | LOAD_LENGTH(len))

/**
 * @brief  FIFO Load to register \a dst class \a cla with action \a act.
 *
 */
#define FIFO_LD(cla, dst, act, len) \
			(CMD_FIFO_LOAD_TYPE | CMD_CLASS(cla) |		\
			FIFO_LOAD_INPUT(dst) | FIFO_LOAD_ACTION(act) |	\
			FIFO_LOAD_LENGTH(len))

/**
 * @brief  FIFO Load to register \a dst class \a cla with action \a act.
 *         Pointer is a Scatter/Gatter Table
 *
 */
#define FIFO_LD_SGT(cla, dst, act, len) \
			(CMD_FIFO_LOAD_TYPE | CMD_CLASS(cla) | CMD_SGT | \
			FIFO_LOAD_INPUT(dst) | FIFO_LOAD_ACTION(act) |   \
			FIFO_LOAD_LENGTH(len))

/**
 * @brief  FIFO Load to register \a dst class \a cla with action \a act. \n
 *         The length is externally defined
 *
 */
#define FIFO_LD_EXT(cla, dst, act) \
			(CMD_FIFO_LOAD_TYPE | FIFO_LOAD_EXT |	\
			CMD_CLASS(cla) | FIFO_LOAD_INPUT(dst) |	\
			FIFO_LOAD_ACTION(act))

/**
 * @brief  FIFO Load Immediate data length \a len to register \a dst
 *         class \a cla with action \a act.
 *
 */
#define FIFO_LD_IMM(cla, dst, act, len) \
			(CMD_FIFO_LOAD_TYPE | CMD_IMM |			\
			CMD_CLASS(cla) | FIFO_LOAD_INPUT(dst) |		\
			FIFO_LOAD_ACTION(act) | FIFO_LOAD_LENGTH(len))

/**
 * @brief  Store value of length \a len from register \a src of
 *         class \a cla
 */
#define ST_NOIMM(cla, src, len) \
			(CMD_STORE_TYPE | CMD_CLASS(cla) | STORE_SRC(src) | \
			STORE_LENGTH(len))

/**
 * @brief  Store value of length \a len from register \a src of
 *         class \a cla starting at register offset \a off
 */
#define ST_NOIMM_OFF(cla, src, len, off) \
			(CMD_STORE_TYPE | CMD_CLASS(cla) | STORE_SRC(src) | \
			STORE_OFFSET(off) | STORE_LENGTH(len))

/**
 * @brief  FIFO Store from register \a src of length \a len
 */
#define FIFO_ST(src, len) \
			(CMD_FIFO_STORE_TYPE | FIFO_STORE_OUTPUT(src) | \
			FIFO_STORE_LENGTH(len))

/**
 * @brief  FIFO Store from register \a src. \n
 *         The length is externally defined
 */
#define FIFO_ST_EXT(src) \
			(CMD_FIFO_STORE_TYPE | FIFO_LOAD_EXT | \
			 FIFO_STORE_OUTPUT(src))

/**
 * @brief  FIFO Store from register \a src of length \a len. Pointer is
 *         a Scatter/Gatter Table
 */
#define FIFO_ST_SGT(src, len) \
			(CMD_FIFO_STORE_TYPE | CMD_SGT | \
			 FIFO_STORE_OUTPUT(src) | FIFO_STORE_LENGTH(len))

/**
 * @brief  RNG State Handle instantation operation for \a sh id
 */
#define RNG_SH_INST(sh) \
			(CMD_OP_TYPE | OP_TYPE(CLASS1) | OP_ALGO(RNG) | \
			ALGO_RNG_SH(sh) | ALGO_AS(RNG_INSTANTIATE))

/**
 * @brief  RNG Generates Secure Keys
 */
#define RNG_GEN_SECKEYS \
			(CMD_OP_TYPE | OP_TYPE(CLASS1) | OP_ALGO(RNG) | \
			ALGO_RNG_SK | ALGO_AS(RNG_GENERATE))

/**
 * @brief  RNG Generates Data
 */
#define RNG_GEN_DATA \
			(CMD_OP_TYPE | OP_TYPE(CLASS1) | OP_ALGO(RNG) | \
			 ALGO_AS(RNG_GENERATE))

/**
 * @brief  HASH Init Operation of algorithm \a algo
 */
#define HASH_INIT(algo) \
			(CMD_OP_TYPE | OP_TYPE(CLASS2) | (algo) | \
			ALGO_AS(INIT) | ALGO_ENCRYPT)

/**
 * @brief  HASH Update Operation of algorithm \a algo
 */
#define HASH_UPDATE(algo) \
			(CMD_OP_TYPE | OP_TYPE(CLASS2) | (algo) | \
			ALGO_AS(UPDATE) | ALGO_ENCRYPT)

/**
 * @brief  HASH Final Operation of algorithm \a algo
 */
#define HASH_FINAL(algo) \
			(CMD_OP_TYPE | OP_TYPE(CLASS2) | (algo) | \
			ALGO_AS(FINAL) | ALGO_ENCRYPT)

/**
 * @brief  HASH Init and Final Operation of algorithm \a algo
 */
#define HASH_INITFINAL(algo) \
			(CMD_OP_TYPE | OP_TYPE(CLASS2) | (algo) | \
			ALGO_AS(INIT_FINAL) | ALGO_ENCRYPT)

/**
 * @brief  HMAC Init Decryption Operation of algorithm \a algo
 */
#define HMAC_INIT_DECRYPT(algo) \
			(CMD_OP_TYPE | OP_TYPE(CLASS2) | (algo) | \
			ALGO_AS(INIT) | ALGO_AAI(DIGEST_HMAC) | ALGO_DECRYPT)

/**
 * @brief  HMAC Init Operation of algorithm \a algo with Precomp key
 */
#define HMAC_INITFINAL_PRECOMP(algo) \
			(CMD_OP_TYPE | OP_TYPE(CLASS2) | (algo) | \
			ALGO_AS(INIT_FINAL) | ALGO_AAI(DIGEST_HMAC_PRECOMP) | \
			ALGO_ENCRYPT)

/**
 * @brief  HMAC Init and Final Operation of algorithm \a algo with Precomp key
 */
#define HMAC_INIT_PRECOMP(algo) \
			(CMD_OP_TYPE | OP_TYPE(CLASS2) | (algo) | \
			ALGO_AS(INIT) | ALGO_AAI(DIGEST_HMAC_PRECOMP) | \
			ALGO_ENCRYPT)
/**
 * @brief  HMAC Final Operation of algorithm \a algo with Precomp key
 */
#define HMAC_FINAL_PRECOMP(algo) \
			(CMD_OP_TYPE | OP_TYPE(CLASS2) | (algo) | \
			ALGO_AS(FINAL) | ALGO_AAI(DIGEST_HMAC_PRECOMP) | \
			ALGO_ENCRYPT)

/**
 * @brief  Cipher Init and Final Operation of algorithm \a algo
 */
#define CIPHER_INITFINAL(algo, encrypt) \
			(CMD_OP_TYPE | OP_TYPE(CLASS1) | (algo) | \
			 ALGO_AS(INIT_FINAL) | \
			((encrypt == true) ? ALGO_ENCRYPT : ALGO_DECRYPT))

/**
 * @brief  Cipher Init Operation of algorithm \a algo
 */
#define CIPHER_INIT(algo, encrypt) \
			(CMD_OP_TYPE | OP_TYPE(CLASS1) | (algo) | \
			 ALGO_AS(INIT) | \
			((encrypt == true) ? ALGO_ENCRYPT : ALGO_DECRYPT))

/**
 * @brief  Cipher Update Operation of algorithm \a algo
 */
#define CIPHER_UPDATE(algo, encrypt) \
			(CMD_OP_TYPE | OP_TYPE(CLASS1) | (algo) | \
			 ALGO_AS(UPDATE) | \
			((encrypt == true) ? ALGO_ENCRYPT : ALGO_DECRYPT))

/**
 * @brief  Cipher Final Operation of algorithm \a algo
 */
#define CIPHER_FINAL(algo, encrypt) \
			(CMD_OP_TYPE | OP_TYPE(CLASS1) | (algo) | \
			 ALGO_AS(FINAL) | \
			((encrypt == true) ? ALGO_ENCRYPT : ALGO_DECRYPT))

/**
 * @brief   Load a class \a cla key of length \a len to register \a dst.
 *          Key can be store in plain text.
 */
#define LD_KEY_PLAIN(cla, dst, len) \
			(CMD_KEY_TYPE | CMD_CLASS(cla) | KEY_PTS | \
			KEY_DEST(dst) | KEY_LENGTH(len))

/**
 * @brief   Load a split key of length \a len.
 */
#define LD_KEY_SPLIT(len) \
			(CMD_KEY_TYPE | CMD_CLASS(CLASS_2) | \
			KEY_DEST(MDHA_SPLIT) | \
			KEY_LENGTH(len))

/**
 * @brief  MPPRIVK generation function.
 */
#define MPPRIVK \
			(CMD_OP_TYPE | OP_TYPE(ENCAPS) | PROTID(MPKEY))

/**
 * @brief  MPPUBK generation function.
 */
#define MPPUBK \
			(CMD_OP_TYPE | OP_TYPE(DECAPS) | PROTID(MPKEY))

/**
 * @brief  MPSIGN function.
 */
#define MPSIGN_OP \
			(CMD_OP_TYPE | OP_TYPE(DECAPS) | PROTID(MPSIGN))

/**
 * @brief   Operation Mathematical of length \a len
 *          \a dest = \a src0 (operation \a func) \a src1
 */
#define MATH(func, src0, src1, dst, len) \
			(CMD_MATH_TYPE | MATH_FUNC(func) | \
			MATH_SRC0(src0) | MATH_SRC1(src1) | \
			MATH_DST(dst) | MATH_LENGTH(len))
/**
 * @brief   Operation Mathematical  of length \a len
 *          using an immediate value as operand 1
 *          \a dest = \a src (operation \a func) \a val
 */
#define MATHI_OP1(func, src, val, dst, len) \
			(CMD_MATHI_TYPE | MATH_FUNC(func) | \
			MATHI_SRC(src) | MATHI_IMM_VALUE(val) | \
			MATHI_DST(dst) | MATH_LENGTH(len))

/**
 * @brief   PKHA Copy function from \a src to \a dst. Copy number
 *          of words specified in Source size register
 */
#define PKHA_CPY_SSIZE(src, dst) \
			(CMD_OP_TYPE | OP_TYPE(PKHA) | PKHA_ALG | \
			PKHA_FUNC(CPY_SSIZE) | \
			PKHA_CPY_SRC(src) | PKHA_CPY_DST(dst))

/**
 * @brief   PKHA Operation \a op result into \a dst
 */
#define PKHA_OP(op, dst) \
			(CMD_OP_TYPE | OP_TYPE(PKHA) | PKHA_ALG | \
			PKHA_FUNC(op) | PKHA_OUTSEL(dst))

/**
 * @brief   PKHA Binomial operation \a op result into \a dst
 */
#define PKHA_F2M_OP(op, dst) \
			(CMD_OP_TYPE | OP_TYPE(PKHA) | PKHA_ALG | \
			PKHA_F2M | PKHA_FUNC(op) | PKHA_OUTSEL(dst))

/**
 * @brief   Move \a src to \a dst
 */
#define MOVE(src, dst, off, len) \
			(CMD_MOVE_TYPE | \
			MOVE_SRC(src) | MOVE_DST(dst) | \
			MOVE_OFFSET(off) | MOVE_LENGTH(len))

/**
 * @brief   Move \a src to \a dst and wait until completion
 */
#define MOVE_WAIT(src, dst, off, len) \
			(CMD_MOVE_TYPE | MOVE_WC | \
			MOVE_SRC(src) | MOVE_DST(dst) | \
			MOVE_OFFSET(off) | MOVE_LENGTH(len))

/**
 * @brief   RSA Encryption using format \a format
 */
#define RSA_ENCRYPT(format) \
			(CMD_OP_TYPE | PROTID(RSA_ENC) | \
			 PROT_RSA_FMT(format))

/**
 * @brief   RSA Decryption using format \a format
 */
#define RSA_DECRYPT(format) \
			(CMD_OP_TYPE | PROTID(RSA_DEC) | \
			 PROT_RSA_FMT(format))

/**
 * @brief   RSA Finalize Key in format \a format
 */
#define RSA_FINAL_KEY(format) \
			(CMD_OP_TYPE | PROTID(RSA_FINISH_KEY) | \
			 PROT_RSA_KEY(format))

/**
 * @brief    Public Keypair generation
 */
#define PK_KEYPAIR_GEN(type) \
			(CMD_OP_TYPE | OP_TYPE(UNI) | PROTID(PKKEY) | \
			PROT_PK_TYPE(type))

/**
 * @brief    DSA/ECDSA signature of message hashed
 */
#define DSA_SIGN(type) \
			(CMD_OP_TYPE | OP_TYPE(UNI) | PROTID(DSASIGN) | \
			PROT_PK_MSG(HASHED) | PROT_PK_TYPE(type))
/**
 * @brief    DSA/ECDSA signature verify message hashed
 */
#define DSA_VERIFY(type) \
			(CMD_OP_TYPE | OP_TYPE(UNI) | PROTID(DSAVERIFY) | \
			PROT_PK_MSG(HASHED) | PROT_PK_TYPE(type))
/**
 * @brief    DH/ECC Shared Secret
 */
#define SHARED_SECRET(type) \
			(CMD_OP_TYPE | OP_TYPE(UNI) | PROTID(SHARED_SECRET) | \
			PROT_PK_TYPE(type))

/**
 * @brief   Blob Master Key Verification
 */
#define BLOB_MSTR_KEY \
			(CMD_OP_TYPE | OP_TYPE(ENCAPS) | PROTID(BLOB) | \
			PROT_BLOB_FMT_MSTR)

/**
 * @brief   Blob encapsulation
 */
#define BLOB_ENCAPS \
			(CMD_OP_TYPE | OP_TYPE(ENCAPS) | PROTID(BLOB) | \
			PROT_BLOB_FORMAT(NORMAL))

/**
 * @brief   Blob decapsulation
 */
#define BLOB_DECAPS \
			(CMD_OP_TYPE | OP_TYPE(DECAPS) | PROTID(BLOB) | \
			PROT_BLOB_FORMAT(NORMAL))

/**
 * @brief Black key CCM size
 */
#define BLACK_KEY_CCM_SIZE(size) \
			(ROUNDUP(size, 8) + BLACK_KEY_NONCE_SIZE + \
			BLACK_KEY_ICV_SIZE)
/**
 * @brief Black key ECB size
 */
#define BLACK_KEY_ECB_SIZE(size) \
			ROUNDUP(size, 16)

/**
 * @brief   Sequence Inout Pointer of length \a len
 */
#define SEQ_IN_PTR(len) \
			(CMD_SEQ_IN_TYPE | SEQ_LENGTH(len))

/**
 * @brief   Sequence Output Pointer of length \a len
 */
#define SEQ_OUT_PTR(len) \
			(CMD_SEQ_OUT_TYPE | SEQ_LENGTH(len))

#endif /* __DESC_HELPER_H__ */
