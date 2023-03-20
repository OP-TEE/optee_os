/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2018-2021, 2024 NXP
 *
 * Brief   CAAM Descriptor interface.
 */
#ifndef __CAAM_DESC_HELPER_H__
#define __CAAM_DESC_HELPER_H__

#include <caam_desc_defines.h>
#include <caam_jr.h>
#include <caam_utils_dmaobj.h>
#include <trace.h>

/*
 * Returns the number of entries of the descriptor
 */
uint32_t caam_desc_get_len(uint32_t *desc);

/* Descriptor Modification function */
void caam_desc_init(uint32_t *desc);
void caam_desc_update_hdr(uint32_t *desc, uint32_t word);
void caam_desc_add_ptr(uint32_t *desc, paddr_t ptr);
void caam_desc_add_word(uint32_t *desc, uint32_t word);
void caam_desc_add_dmaobj(uint32_t *desc, struct caamdmaobj *data,
			  uint32_t pre_operation);

#define caam_desc_fifo_load(desc, data, cla, dst, act)                         \
	caam_desc_add_dmaobj(desc, data, FIFO_LD(cla, dst, act, 0))
#define caam_desc_load_key(desc, data, cla, dst)                               \
	caam_desc_add_dmaobj(desc, data, LD_KEY_PLAIN(cla, dst, 0))
#define caam_desc_store(desc, data, cla, src)                                  \
	caam_desc_add_dmaobj(desc, data, ST_NOIMM(cla, src, 0))
#define caam_desc_fifo_store(desc, data, src)                                  \
	caam_desc_add_dmaobj(desc, data, FIFO_ST(CLASS_NO, src, 0))
#define caam_desc_seq_out(desc, data)                                          \
	caam_desc_add_dmaobj(desc, data, SEQ_OUT_PTR(0))

/* Push/Pop descriptor rings queue */
void caam_desc_push(struct caam_inring_entry *in_entry, paddr_t paddr);
paddr_t caam_desc_pop(struct caam_outring_entry *out_entry);

uint32_t caam_read_jobstatus(struct caam_outring_entry *out);

/* Debug print function to dump a Descriptor in hex */
static inline void dump_desc(uint32_t *desc)
{
	size_t idx = 0;
	size_t len = 0;

	len = caam_desc_get_len(desc);

	for (idx = 0; idx < len; idx++)
		trace_printf(NULL, 0, 0, false, "[%02zu] %08" PRIX32, idx,
			     desc[idx]);
}

/*
 * Returns the descriptor size in bytes of nbEntries
 */
#define DESC_SZBYTES(nbentries) ((nbentries) * sizeof(uint32_t))

/*
 * Descriptor Header starting at idx w/o descriptor length
 */
#define DESC_HDR(idx) (CMD_HDR_JD_TYPE | HDR_JD_ONE | HDR_JD_START_IDX(idx))

/*
 * Descriptor Header starting at index 0 with descriptor length len
 */
#define DESC_HEADER(len) (DESC_HDR(0) | HDR_JD_DESCLEN(len))

/*
 * Descriptor Header starting at idx with descriptor length len
 */
#define DESC_HEADER_IDX(len, idx) (DESC_HDR(idx) | HDR_JD_DESCLEN(len))

/*
 * Jump Local of class cla to descriptor offset if test meet the
 * condition cond
 */
#define JUMP_LOCAL(cla, test, cond, offset)                                    \
	(CMD_JUMP_TYPE | CMD_CLASS(cla) | JUMP_TYPE(LOCAL) |                   \
	 JUMP_TST_TYPE(test) | (cond) | JMP_LOCAL_OFFSET(offset))

/*
 * Jump Local of no class to descriptor offset if test meet the
 * condition cond
 */
#define JUMP_CNO_LOCAL(test, cond, offset)                                     \
	JUMP_LOCAL(CLASS_NO, test, cond, offset)

/*
 * Jump Local of class 1 to descriptor offset if test meet the
 * condition cond
 */
#define JUMP_C1_LOCAL(test, cond, offset)                                      \
	JUMP_LOCAL(CLASS_1, test, cond, offset)

/*
 * First decrement specified source then
 * Jump Local of no class to descriptor offset if test meet the
 * condition cond
 */
#define JUMP_CNO_LOCAL_DEC(test, src, cond, offset)                            \
	(CMD_JUMP_TYPE | CMD_CLASS(CLASS_NO) | JUMP_TYPE(LOCAL_DEC) |          \
	 JUMP_TST_TYPE(test) | JMP_SRC(src) | (cond) |                         \
	 JMP_LOCAL_OFFSET(offset))

/*
 * Wait until test condition meet and jump next
 */
#define WAIT_COND(test, cond)                                                  \
	(JUMP_LOCAL(CLASS_NO, test, JMP_COND(cond), 1) | JMP_JSL)

/*
 * Jump No Local of class cla to descriptor offset if test meet the
 * condition cond
 */
#define JUMP_NOTLOCAL(cla, test, cond)                                         \
	(CMD_JUMP_TYPE | CMD_CLASS(cla) | JUMP_TYPE(NON_LOCAL) |               \
	 JUMP_TST_TYPE(test) | (cond))

/*
 * User Halt with error if test meet the condition cond
 */
#define HALT_USER(test, cond, error)                                           \
	(CMD_JUMP_TYPE | JUMP_TYPE(HALT_USER_STATUS) | JUMP_TST_TYPE(test) |   \
	 JMP_COND(cond) | JMP_LOCAL_OFFSET(error))

/*
 * Load Immediate value of length len to register dst of class cla
 */
#define LD_IMM(cla, dst, len)                                                  \
	(CMD_LOAD_TYPE | CMD_CLASS(cla) | CMD_IMM | LOAD_DST(dst) |            \
	 LOAD_LENGTH(len))

/*
 * Load Immediate value of length len to register dst of class starting of
 * register offset.
 */
#define LD_IMM_OFF(cla, dst, len, off)                                         \
	(CMD_LOAD_TYPE | CMD_CLASS(cla) | CMD_IMM | LOAD_DST(dst) |            \
	 LOAD_OFFSET(off) | LOAD_LENGTH(len))

/*
 * Load Immediate value of length len to register dst w/o class
 */
#define LD_NOCLASS_IMM(dst, len) LD_IMM(CLASS_NO, dst, len)

/*
 * Load value of length len to register dst of class cla
 */
#define LD_NOIMM(cla, dst, len)                                                \
	(CMD_LOAD_TYPE | CMD_CLASS(cla) | LOAD_DST(dst) | LOAD_LENGTH(len))

/*
 * Load value of length len to register dst of class cla starting
 * at register offset off
 */
#define LD_NOIMM_OFF(cla, dst, len, off)                                       \
	(CMD_LOAD_TYPE | CMD_CLASS(cla) | LOAD_DST(dst) | LOAD_OFFSET(off) |   \
	 LOAD_LENGTH(len))

/*
 * FIFO Load to register dst class cla with action act
 */
#define FIFO_LD(cla, dst, act, len)                                            \
	(CMD_FIFO_LOAD_TYPE | CMD_CLASS(cla) | FIFO_LOAD_INPUT(dst) |          \
	 FIFO_LOAD_ACTION(act) | FIFO_LOAD_LENGTH(len))

/*
 * FIFO Load to register dst class cla with action act.
 * Pointer is a Scatter/Gather Table
 */
#define FIFO_LD_SGT(cla, dst, act, len)                                        \
	(CMD_FIFO_LOAD_TYPE | CMD_CLASS(cla) | CMD_SGT |                       \
	 FIFO_LOAD_INPUT(dst) | FIFO_LOAD_ACTION(act) | FIFO_LOAD_LENGTH(len))

/*
 * FIFO Load to register dst class cla with action act.
 * Pointer is a Scatter/Gather Table
 * The length is externally defined
 */
#define FIFO_LD_SGT_EXT(cla, dst, act)                                         \
	(CMD_FIFO_LOAD_TYPE | CMD_CLASS(cla) | CMD_SGT | FIFO_LOAD_EXT |       \
	 FIFO_LOAD_INPUT(dst) | FIFO_LOAD_ACTION(act))

/*
 * FIFO Load to register dst class cla with action act.
 * The length is externally defined
 */
#define FIFO_LD_EXT(cla, dst, act)                                             \
	(CMD_FIFO_LOAD_TYPE | FIFO_LOAD_EXT | CMD_CLASS(cla) |                 \
	 FIFO_LOAD_INPUT(dst) | FIFO_LOAD_ACTION(act))

/*
 * FIFO Load Immediate data length len to register dst class cla
 * with action act.
 */
#define FIFO_LD_IMM(cla, dst, act, len)                                        \
	(CMD_FIFO_LOAD_TYPE | CMD_IMM | CMD_CLASS(cla) |                       \
	 FIFO_LOAD_INPUT(dst) | FIFO_LOAD_ACTION(act) | FIFO_LOAD_LENGTH(len))

/*
 * Store value of length len from register src of class cla
 */
#define ST_NOIMM(cla, src, len)                                                \
	(CMD_STORE_TYPE | CMD_CLASS(cla) | STORE_SRC(src) | STORE_LENGTH(len))

/*
 * Store value of length len from register src of class cla
 * Pointer is a Scatter/Gather Table
 */
#define ST_SGT_NOIMM(cla, src, len)                                            \
	(CMD_STORE_TYPE | CMD_CLASS(cla) | CMD_SGT | STORE_SRC(src) |          \
	 STORE_LENGTH(len))

/*
 * Store value of length len from register src of class cla starting
 * at register offset off
 */
#define ST_NOIMM_OFF(cla, src, len, off)                                       \
	(CMD_STORE_TYPE | CMD_CLASS(cla) | STORE_SRC(src) |                    \
	 STORE_OFFSET(off) | STORE_LENGTH(len))

/*
 * Store value of length len from register src of class cla
 */
#define ST_NOIMM_SEQ(cla, src, len)                                            \
	(CMD_STORE_SEQ_TYPE | CMD_CLASS(cla) | STORE_SRC(src) |                \
	 STORE_LENGTH(len))

/*
 * FIFO Store from register src of length len
 */
#define FIFO_ST(cla, src, len)                                                 \
	(CMD_FIFO_STORE_TYPE | CMD_CLASS(cla) | FIFO_STORE_OUTPUT(src) |       \
	 FIFO_STORE_LENGTH(len))

/*
 * FIFO Store from register src.
 * The length is externally defined
 */
#define FIFO_ST_EXT(src)                                                       \
	(CMD_FIFO_STORE_TYPE | FIFO_STORE_EXT | FIFO_STORE_OUTPUT(src))

/*
 * FIFO Store from register src of length len.
 * Pointer is a Scatter/Gather Table
 */
#define FIFO_ST_SGT(src, len)                                                  \
	(CMD_FIFO_STORE_TYPE | CMD_SGT | FIFO_STORE_OUTPUT(src) |              \
	 FIFO_STORE_LENGTH(len))

/*
 * FIFO Store from register src.
 * Pointer is a Scatter/Gather Table
 * The length is externally defined
 */
#define FIFO_ST_SGT_EXT(src)                                                   \
	(CMD_FIFO_STORE_TYPE | CMD_SGT | FIFO_STORE_EXT |                      \
	 FIFO_STORE_OUTPUT(src))

/*
 * SEQ FIFO Store from register src of length len
 */
#define FIFO_ST_SEQ(src, len)                                                  \
	(CMD_SEQ_FIFO_STORE_TYPE | FIFO_STORE_OUTPUT(src) |                    \
	 FIFO_STORE_LENGTH(len))

/*
 * RNG State Handle instantation operation for sh ID
 */
#define RNG_SH_INST(sh)                                                        \
	(CMD_OP_TYPE | OP_TYPE(CLASS1) | OP_ALGO(RNG) | ALGO_RNG_SH(sh) |      \
	 ALGO_AS(RNG_INSTANTIATE) | ALGO_RNG_PR)

/*
 * RNG Generates Secure Keys
 */
#define RNG_GEN_SECKEYS                                                        \
	(CMD_OP_TYPE | OP_TYPE(CLASS1) | OP_ALGO(RNG) | ALGO_RNG_SK |          \
	 ALGO_AS(RNG_GENERATE))

/*
 * RNG Generates Data
 */
#define RNG_GEN_DATA                                                           \
	(CMD_OP_TYPE | OP_TYPE(CLASS1) | OP_ALGO(RNG) | ALGO_AS(RNG_GENERATE))

/*
 * Hash Init Operation of algorithm algo
 */
#define HASH_INIT(algo)                                                        \
	(CMD_OP_TYPE | OP_TYPE(CLASS2) | (algo) | ALGO_AS(INIT) | ALGO_ENCRYPT)

/*
 * Hash Update Operation of algorithm algo
 */
#define HASH_UPDATE(algo)                                                      \
	(CMD_OP_TYPE | OP_TYPE(CLASS2) | (algo) | ALGO_AS(UPDATE) |            \
	 ALGO_ENCRYPT)

/*
 * Hash Final Operation of algorithm algo
 */
#define HASH_FINAL(algo)                                                       \
	(CMD_OP_TYPE | OP_TYPE(CLASS2) | (algo) | ALGO_AS(FINAL) | ALGO_ENCRYPT)

/*
 * Hash Init and Final Operation of algorithm algo
 */
#define HASH_INITFINAL(algo)                                                   \
	(CMD_OP_TYPE | OP_TYPE(CLASS2) | (algo) | ALGO_AS(INIT_FINAL) |        \
	 ALGO_ENCRYPT)

/*
 * HMAC Init Decryption Operation of algorithm algo
 */
#define HMAC_INIT_DECRYPT(algo)                                                \
	(CMD_OP_TYPE | OP_TYPE(CLASS2) | (algo) | ALGO_AS(INIT) |              \
	 ALGO_AAI(DIGEST_HMAC) | ALGO_DECRYPT)

/*
 * HMAC Init and Final Operation of algorithm algo with Precomp key
 */
#define HMAC_INITFINAL_PRECOMP(algo)                                           \
	(CMD_OP_TYPE | OP_TYPE(CLASS2) | (algo) | ALGO_AS(INIT_FINAL) |        \
	 ALGO_AAI(DIGEST_HMAC_PRECOMP) | ALGO_ENCRYPT)

/*
 * HMAC Init Operation of algorithm algo with Precomp key
 */
#define HMAC_INIT_PRECOMP(algo)                                                \
	(CMD_OP_TYPE | OP_TYPE(CLASS2) | (algo) | ALGO_AS(INIT) |              \
	 ALGO_AAI(DIGEST_HMAC_PRECOMP) | ALGO_ENCRYPT)

/*
 * HMAC Final Operation of algorithm algo with Precomp key
 */
#define HMAC_FINAL_PRECOMP(algo)                                               \
	(CMD_OP_TYPE | OP_TYPE(CLASS2) | (algo) | ALGO_AS(FINAL) |             \
	 ALGO_AAI(DIGEST_HMAC_PRECOMP) | ALGO_ENCRYPT)

/*
 * Cipher Init and Final Operation of algorithm algo
 */
#define CIPHER_INITFINAL(algo, encrypt)                                        \
	(CMD_OP_TYPE | OP_TYPE(CLASS1) | (algo) | ALGO_AS(INIT_FINAL) |        \
	 ((encrypt) ? ALGO_ENCRYPT : ALGO_DECRYPT))

/*
 * Cipher Init Operation of algorithm algo
 */
#define CIPHER_INIT(algo, encrypt)                                             \
	(CMD_OP_TYPE | OP_TYPE(CLASS1) | (algo) | ALGO_AS(INIT) |              \
	 ((encrypt) ? ALGO_ENCRYPT : ALGO_DECRYPT))

/*
 * Cipher Update Operation of algorithm algo
 */
#define CIPHER_UPDATE(algo, encrypt)                                           \
	(CMD_OP_TYPE | OP_TYPE(CLASS1) | (algo) | ALGO_AS(UPDATE) |            \
	 ((encrypt) ? ALGO_ENCRYPT : ALGO_DECRYPT))

/*
 * Cipher Final Operation of algorithm algo
 */
#define CIPHER_FINAL(algo, encrypt)                                            \
	(CMD_OP_TYPE | OP_TYPE(CLASS1) | (algo) | ALGO_AS(FINAL) |             \
	 ((encrypt) ? ALGO_ENCRYPT : ALGO_DECRYPT))

/*
 * Load a class cla key of length len to register dst.
 * Key can be stored in plain text.
 */
#define LD_KEY_PLAIN(cla, dst, len)                                            \
	(CMD_KEY_TYPE | CMD_CLASS(cla) | KEY_PTS | KEY_DEST(dst) |             \
	 KEY_LENGTH(len))

/*
 * Load a class cla key of length len to register dst.
 * Key can be stored in plain text.
 * Pointer is a Scatter/Gatter Table
 */
#define LD_KEY_SGT_PLAIN(cla, dst, len)                                        \
	(CMD_KEY_TYPE | CMD_CLASS(cla) | CMD_SGT | KEY_PTS | KEY_DEST(dst) |   \
	 KEY_LENGTH(len))

/*
 * Load a split key of length len.
 */
#define LD_KEY_SPLIT(len)                                                      \
	(CMD_KEY_TYPE | CMD_CLASS(CLASS_2) | KEY_DEST(MDHA_SPLIT) |            \
	 KEY_LENGTH(len))

/*
 * Load a class cla key of length len to register dst.
 */
#define LD_KEY(cla, dst, len)                                                  \
	(CMD_KEY_TYPE | CMD_CLASS(cla) | KEY_DEST(dst) | KEY_LENGTH(len))

/*
 * MPPRIVK generation function.
 */
#define MPPRIVK (CMD_OP_TYPE | OP_TYPE(ENCAPS) | PROTID(MPKEY))

/*
 * MPPUBK generation function.
 */
#define MPPUBK (CMD_OP_TYPE | OP_TYPE(DECAPS) | PROTID(MPKEY))

/*
 * MPSIGN function.
 */
#define MPSIGN_OP (CMD_OP_TYPE | OP_TYPE(DECAPS) | PROTID(MPSIGN))

/*
 * Operation Mathematical of length len
 *     dest = src0 (operation func) src1
 */
#define MATH(func, src0, src1, dst, len)                                       \
	(CMD_MATH_TYPE | MATH_FUNC(func) | MATH_SRC0(src0) | MATH_SRC1(src1) | \
	 MATH_DST(dst) | MATH_LENGTH(len))

/*
 * Operation Mathematical of length len using an immediate value as operand 1
 *     dest = src (operation func) val
 */
#define MATHI_OP1(func, src, val, dst, len)                                    \
	(CMD_MATHI_TYPE | MATH_FUNC(func) | MATHI_SRC(src) |                   \
	 MATHI_IMM_VALUE(val) | MATHI_DST(dst) | MATH_LENGTH(len))

/*
 * PKHA Copy function from src to dst. Copy number of words specified
 * in Source size register
 */
#define PKHA_CPY_SSIZE(src, dst)                                               \
	(CMD_OP_TYPE | OP_TYPE(PKHA) | PKHA_ALG | PKHA_FUNC(CPY_SSIZE) |       \
	 PKHA_CPY_SRC(src) | PKHA_CPY_DST(dst))

/*
 * PKHA Copy N-Size function from src to dst. Copy number of words specified
 * in PKHA N size register
 */
#define PKHA_CPY_NSIZE(src, dst)                                               \
	(CMD_OP_TYPE | OP_TYPE(PKHA) | PKHA_ALG | PKHA_FUNC(CPY_NSIZE) |       \
	 PKHA_CPY_SRC(src) | PKHA_CPY_DST(dst))

/*
 * PKHA Operation op result into dst
 */
#define PKHA_OP(op, dst)                                                       \
	(CMD_OP_TYPE | OP_TYPE(PKHA) | PKHA_ALG | PKHA_FUNC(op) |              \
	 PKHA_OUTSEL(dst))

/*
 * PKHA Binomial operation op result into dst
 */
#define PKHA_F2M_OP(op, dst)                                                   \
	(CMD_OP_TYPE | OP_TYPE(PKHA) | PKHA_ALG | PKHA_F2M | PKHA_FUNC(op) |   \
	 PKHA_OUTSEL(dst))

/*
 * Move src to dst
 */
#define MOVE(src, dst, off, len)                                               \
	(CMD_MOVE_TYPE | MOVE_SRC(src) | MOVE_DST(dst) | MOVE_OFFSET(off) |    \
	 MOVE_LENGTH(len))

/*
 * Move src to dst and wait until completion
 */
#define MOVE_WAIT(src, dst, off, len)                                          \
	(CMD_MOVE_TYPE | MOVE_WC | MOVE_SRC(src) | MOVE_DST(dst) |             \
	 MOVE_OFFSET(off) | MOVE_LENGTH(len))

/*
 * RSA Encryption using format
 */
#define RSA_ENCRYPT(format)                                                    \
	(CMD_OP_TYPE | PROTID(RSA_ENC) | PROT_RSA_FMT(format))

/*
 * RSA Decryption using format
 */
#define RSA_DECRYPT(format)                                                    \
	(CMD_OP_TYPE | PROTID(RSA_DEC) | PROT_RSA_FMT(format))

/*
 * RSA Finalize Key in format
 */
#define RSA_FINAL_KEY(format, alg)                                             \
	(CMD_OP_TYPE | PROTID(RSA_FINISH_KEY) | PROT_RSA_KEY(format) |         \
	 PROT_RSA_FINISH_KEY(alg))

/*
 * Public Keypair generation
 */
#define PK_KEYPAIR_GEN(type, alg)                                              \
	(CMD_OP_TYPE | OP_TYPE(UNI) | PROTID(PKKEY) | PROT_PK_TYPE(type) |     \
	 PROT_PRI(alg))

/*
 * DSA/ECDSA signature of message of msg_type
 */
#define DSA_SIGN(type, msg_type, alg) \
	(CMD_OP_TYPE | OP_TYPE(UNI) | PROTID(DSASIGN) | \
	 PROT_PK_MSG(msg_type) | PROT_PK_TYPE(type) | PROT_PRI(alg))

/*
 * DSA/ECDSA signature verify message of msg_type
 */
#define DSA_VERIFY(type, msg_type)                        \
	(CMD_OP_TYPE | OP_TYPE(UNI) | PROTID(DSAVERIFY) | \
	 PROT_PK_MSG(msg_type) | PROT_PK_TYPE(type))

/*
 * DH/ECC Shared Secret
 */
#define SHARED_SECRET(type, alg)                                               \
	(CMD_OP_TYPE | OP_TYPE(UNI) | PROTID(SHARED_SECRET) |                  \
	 PROT_PK_TYPE(type) | PROT_PRI(alg))

/*
 * Blob Master Key Verification
 */
#define BLOB_MSTR_KEY                                                          \
	(CMD_OP_TYPE | OP_TYPE(ENCAPS) | PROTID(BLOB) | PROT_BLOB_FMT_MSTR)

/*
 * Blob encapsulation
 */
#define BLOB_ENCAPS                                                            \
	(CMD_OP_TYPE | OP_TYPE(ENCAPS) | PROTID(BLOB) |                        \
	 PROT_BLOB_FORMAT(NORMAL))

/*
 * Blob decapsulation
 */
#define BLOB_DECAPS                                                            \
	(CMD_OP_TYPE | OP_TYPE(DECAPS) | PROTID(BLOB) |                        \
	 PROT_BLOB_FORMAT(NORMAL))

/*
 * Black key CCM size
 */
#define BLACK_KEY_CCM_SIZE(size)                                               \
	(ROUNDUP(size, 8) + BLACK_KEY_NONCE_SIZE + BLACK_KEY_ICV_SIZE)

/*
 * Black key ECB size
 */
#define BLACK_KEY_ECB_SIZE(size) ROUNDUP(size, 16)

/*
 * Sequence Inout Pointer of length len
 */
#define SEQ_IN_PTR(len) (CMD_SEQ_IN_TYPE | SEQ_LENGTH(len))

/*
 * Sequence Output Pointer of length len
 */
#define SEQ_OUT_PTR(len) (CMD_SEQ_OUT_TYPE | SEQ_LENGTH(len))

#endif /* __CAAM_DESC_HELPER_H__ */
