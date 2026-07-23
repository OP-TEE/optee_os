/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc.
 *
 * Shared CRYPTO0 CE block cipher and AEAD helpers.
 */

#ifndef CE_H
#define CE_H

#include <ce_regs.h>
#include <tee_api_types.h>
#include <types_ext.h>

/* ce_get_base() - Return the virtual base address of CRYPTO_REG. */
vaddr_t ce_get_base(void);

/*
 * ce_lock() / ce_unlock() - Serialize access to the shared CRYPTO0 CE block.
 * Callers must hold this lock for the full register-program + transfer
 * sequence of each update() call.
 */
void ce_lock(void);
void ce_unlock(void);

void ce_load_key(vaddr_t base, const uint8_t *key, size_t key_len);
void ce_load_auth_key(vaddr_t base, const uint8_t *key, size_t key_len);
void ce_load_iv(vaddr_t base, const uint8_t iv[TEE_AES_BLOCK_SIZE]);
void ce_load_iv_gcm(vaddr_t base, const uint8_t iv[TEE_AES_BLOCK_SIZE]);
void ce_read_iv(vaddr_t base, uint8_t iv[TEE_AES_BLOCK_SIZE]);
void ce_load_auth_iv(vaddr_t base, const uint32_t auth_iv[CE_AUTH_IV_WORDS]);
void ce_read_auth_iv(vaddr_t base, uint32_t auth_iv[CE_AUTH_IV_WORDS]);
void ce_load_auth_byte_cnt(vaddr_t base, const uint32_t cnt[4]);
void ce_read_auth_byte_cnt(vaddr_t base, uint32_t cnt[4]);
void ce_load_info_nonce(vaddr_t base, const uint32_t nonce[4]);
uint32_t ce_encr_cfg(uint32_t mode, size_t key_len, bool encrypt);
uint32_t ce_encr_cfg_last(uint32_t mode, size_t key_len, bool encrypt);
uint32_t ce_auth_cfg(uint32_t mode, size_t key_len, bool encrypt,
		     bool first, bool last, size_t tag_len);

/*
 * ce_aes_xfer() - Encrypt or decrypt @len bytes (cipher-only).
 * Caller must load IV/key before. Call ce_read_iv() after to read back
 * the updated IV if needed (CBC: last ciphertext block).
 */
TEE_Result ce_aes_xfer(vaddr_t base, uint32_t encr_cfg,
		       const uint8_t *in, uint8_t *out, size_t len);

/*
 * ce_aes_aead_auth() - Feed @aad_len bytes of AAD through the auth engine.
 * Caller must load/save AUTH_IVn/AUTH_BYTECNTn around each call.
 */
TEE_Result ce_aes_aead_auth(vaddr_t base, uint32_t encr_cfg, uint32_t auth_cfg,
			    const uint8_t *aad, size_t aad_len);

/*
 * ce_aes_aead_xfer() - Encrypt/decrypt @len bytes with simultaneous auth.
 * Caller must load/save AUTH_IVn/AUTH_BYTECNTn around each call. On the
 * last segment, @tag/@tag_len carry the tag through the FIFO; pass tag_len=0
 * for non-final segments.
 */
TEE_Result ce_aes_aead_xfer(vaddr_t base, uint32_t encr_cfg,
			    uint32_t auth_cfg,
			    const uint8_t *in, uint8_t *out,
			    size_t len, uint8_t *tag, size_t tag_len,
			    bool encrypt);

#endif /* CE_H */
