// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, Michał Kopeć
 *
 * Hardware unique key from the SEJ (HACC) engine of MediaTek SoCs.
 *
 * The SEJ is an AES engine with a key derived from fuses, which software can't
 * read. Results computed with that key can only be loaded into the key
 * registers of the engine, not read back. The driver derives a working key that
 * way from three fixed blocks, then encrypts a fixed label with the working key
 * and uses the result as the HUK.
 *
 * The SEJ must only be accessible to the secure world, otherwise the normal
 * world can derive the same key: the driver checks that the DEVAPC lets no
 * domain reach the SEJ, or the DEVAPC itself, from the normal world.
 */

#include <io.h>
#include <kernel/delay.h>
#include <kernel/mutex.h>
#include <kernel/tee_common_otp.h>
#include <mm/core_memprot.h>
#include <string.h>
#include <string_ext.h>
#include <trace.h>
#include <util.h>

#define SEJ_SIZE		0x1000

/* Registers of the SEJ */
#define HACC_ACON		0x04	/* Cipher mode and direction */
#define HACC_ACON2		0x08	/* Start, clear and status */
#define HACC_ACONK		0x0c	/* Key selection */
#define HACC_ASRC0		0x10	/* Input block, 4 words */
#define HACC_AKEY0		0x20	/* Key, 8 words */
#define HACC_ACFG0		0x40	/* Initialization vector, 4 words */
#define HACC_AOUT0		0x50	/* Output block, 4 words */

/* HACC_ACON */
#define HACC_AES_DEC		0x0
#define HACC_AES_ENC		0x1
#define HACC_AES_CBC		0x2
#define HACC_AES_128		0x0
/* HACC_ACON2 */
#define HACC_AES_START		0x1
#define HACC_AES_CLR		0x2
#define HACC_AES_RDY		0x8000
/* HACC_ACONK: use the hardware key, and load the results into the key */
#define HACC_AES_BK2C		0x10
#define HACC_AES_R2K		0x100

#define SEJ_TIMEOUT_US		10000

/* Permissions of the INFRA_AO SYS0 modules of the DEVAPC, 2 bits each */
#define DEVAPC_SIZE		0x1000
#define DEVAPC_DOMAINS		16
#define DEVAPC_DOMAIN_OFT	0x40
#define DEVAPC_MODS_PER_REG	16
#define DEVAPC_PERM_MASK	0x3
#define DEVAPC_SEC_RW_ONLY	0x1
#define DEVAPC_FORBIDDEN	0x3

register_phys_mem_pgdir(MEM_AREA_IO_SEC, CFG_MTK_SEJ_BASE, SEJ_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, CFG_MTK_SEJ_DEVAPC_BASE, DEVAPC_SIZE);

/*
 * The IV and the blocks of the key derivation have no meaning of their own.
 * They are the first 16 bytes of the SHA-256 digests of "OP-TEE MediaTek SEJ
 * HUK IV" and "OP-TEE MediaTek SEJ HUK ladder 0" to "... ladder 2", as little
 * endian words. Like the label, they must never change.
 */
static const uint32_t sej_iv[4] = {
	0x47de23cf, 0x2edb8214, 0x9cb1de24, 0xcbade8c3,
};

static const uint32_t sej_ladder[3][4] = {
	{ 0x2301403d, 0xc4f19a4a, 0x1f0ac06a, 0xa1017c1e },
	{ 0x73242242, 0xc2a45802, 0xefcb6a7b, 0x36ce028a },
	{ 0x8c161d29, 0x7356517f, 0x8df75db1, 0x0165acba },
};

/*
 * Label "-optee-huk", version 1. The HUK must never change: secure storage and
 * the RPMB authentication key, which can only be programmed once, derive from
 * it.
 */
static const uint8_t huk_label[16] = {
	'-', 'o', 'p', 't', 'e', 'e', '-', 'h', 'u', 'k', 0, 0, 0, 0, 0, 1,
};

static struct mutex huk_mutex = MUTEX_INITIALIZER;
static uint8_t huk[HW_UNIQUE_KEY_LENGTH];
static bool huk_valid;

/* One AES block of output is the whole HUK */
static_assert(sizeof(huk) == 4 * sizeof(uint32_t));

/* Run one block through the engine, and read the result if out is set. */
static bool sej_block(vaddr_t base, const uint32_t in[4], uint32_t out[4])
{
	unsigned int i = 0;
	uint32_t val = 0;

	for (i = 0; i < 4; i++)
		io_write32(base + HACC_ASRC0 + 4 * i, in[i]);
	io_write32(base + HACC_ACON2, HACC_AES_START);

	if (IO_READ32_POLL_TIMEOUT(base + HACC_ACON2, val,
				   val & HACC_AES_RDY, 0, SEJ_TIMEOUT_US))
		return false;

	if (out)
		for (i = 0; i < 4; i++)
			out[i] = io_read32(base + HACC_AOUT0 + 4 * i);

	return true;
}

static void sej_set_key(vaddr_t base, uint32_t value)
{
	unsigned int i = 0;

	for (i = 0; i < 8; i++)
		io_write32(base + HACC_AKEY0 + 4 * i, value);
}

/* Restart in mode, with the IV */
static void sej_start(vaddr_t base, uint32_t mode, uint32_t key_sel)
{
	unsigned int i = 0;

	io_write32(base + HACC_ACON, HACC_AES_128 | HACC_AES_CBC | mode);
	io_write32(base + HACC_ACONK, key_sel);
	io_write32(base + HACC_ACON2, HACC_AES_CLR);
	for (i = 0; i < 4; i++)
		io_write32(base + HACC_ACFG0 + 4 * i, sej_iv[i]);
}

/* Encrypt the label with the key in the key registers */
static bool sej_encrypt_label(vaddr_t base, uint32_t out[4])
{
	uint32_t label[4] = { };

	sej_start(base, HACC_AES_ENC, 0);
	memcpy(label, huk_label, sizeof(label));
	return sej_block(base, label, out);
}

static void sej_clear(vaddr_t base)
{
	static const uint32_t zero[4] = { };
	unsigned int i = 0;

	io_write32(base + HACC_ACON2, HACC_AES_CLR);
	io_write32(base + HACC_ACON, 0);
	io_write32(base + HACC_ACONK, 0);
	sej_set_key(base, 0);
	for (i = 0; i < 4; i++)
		io_write32(base + HACC_ACFG0 + 4 * i, 0);

	/* Overwrite the output with a block processed with the zero key */
	sej_block(base, zero, NULL);
}

/* Whether no domain can access a module from the normal world */
static bool devapc_secure_only(vaddr_t base, unsigned int module)
{
	vaddr_t reg = base + module / DEVAPC_MODS_PER_REG * 4;
	unsigned int shift = module % DEVAPC_MODS_PER_REG * 2;
	unsigned int d = 0;
	uint32_t perm = 0;

	for (d = 0; d < DEVAPC_DOMAINS; d++) {
		perm = io_read32(reg + d * DEVAPC_DOMAIN_OFT) >> shift;
		perm &= DEVAPC_PERM_MASK;
		if (perm != DEVAPC_SEC_RW_ONLY && perm != DEVAPC_FORBIDDEN)
			return false;
	}

	return true;
}

static TEE_Result sej_derive_huk(void)
{
	vaddr_t base = core_mmu_get_va(CFG_MTK_SEJ_BASE, MEM_AREA_IO_SEC,
				       SEJ_SIZE);
	vaddr_t devapc = core_mmu_get_va(CFG_MTK_SEJ_DEVAPC_BASE,
					 MEM_AREA_IO_SEC, DEVAPC_SIZE);
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t zero_key_out[4] = { };
	uint32_t out[4] = { };
	unsigned int i = 0;

	if (!base || !devapc)
		return TEE_ERROR_GENERIC;

	if (!devapc_secure_only(devapc, CFG_MTK_SEJ_DEVAPC_MODULE) ||
	    !devapc_secure_only(devapc, CFG_MTK_DEVAPC_DEVAPC_MODULE)) {
		EMSG("SEJ isn't secure-only, no hardware unique key");
		return TEE_ERROR_SECURITY;
	}

	/* The label encrypted with an all-zero key, for the check below */
	sej_set_key(base, 0);
	if (!sej_encrypt_label(base, zero_key_out))
		goto timeout;

	/* Load the working key, derived with the hardware key */
	sej_set_key(base, 0);
	sej_start(base, HACC_AES_DEC, HACC_AES_BK2C | HACC_AES_R2K);
	for (i = 0; i < ARRAY_SIZE(sej_ladder); i++)
		if (!sej_block(base, sej_ladder[i], NULL))
			goto timeout;

	if (!sej_encrypt_label(base, out))
		goto timeout;

	/* Without the hardware key, the HUK would be the same everywhere */
	if (!consttime_memcmp(out, zero_key_out, sizeof(out)) ||
	    !(out[0] | out[1] | out[2] | out[3])) {
		EMSG("SEJ ignored its hardware key, no hardware unique key");
		res = TEE_ERROR_SECURITY;
		goto out;
	}

	memcpy(huk, out, sizeof(huk));
	huk_valid = true;
	res = TEE_SUCCESS;
	goto out;

timeout:
	EMSG("SEJ doesn't answer, no hardware unique key");
out:
	sej_clear(base);
	memzero_explicit(out, sizeof(out));

	return res;
}

TEE_Result tee_otp_get_hw_unique_key(struct tee_hw_unique_key *hwkey)
{
	TEE_Result res = TEE_SUCCESS;

	mutex_lock(&huk_mutex);
	if (!huk_valid)
		res = sej_derive_huk();
	if (res == TEE_SUCCESS)
		memcpy(hwkey->data, huk, sizeof(huk));
	mutex_unlock(&huk_mutex);

	return res;
}
