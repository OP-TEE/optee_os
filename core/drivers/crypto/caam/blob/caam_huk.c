// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2019 NXP
 *
 * @file    caam_huk.c
 *
 * @brief   CAAM Generation of a Hardware Unique Key.\n
 *          Use the CAAM Blob Verify Master Key operation
 */
/* Standard includes */
#include <string.h>

/* Global includes */
#include <mm/core_memprot.h>
#include <tee/cache.h>
#include <utee_defines.h>

/* Driver Crypto includes */
#include <drvcrypt.h>
#include <drvcrypt_huk.h>

/* Local includes */
#include "caam_common.h"
#include "caam_huk.h"
#include "caam_jr.h"

/* Utils includes */
#include "utils_mem.h"
#include "utils_status.h"

/**
 * @brief   Blob Key Modifier size in bytes
 */
#define BLOB_KEY_MODIFIER_SIZE	16
/**
 * @brief   Blob Key (BKEK) size in bytes
 */
#define BLOB_BKEK_SIZE			32

/**
 * @brief   Verify Master Key (derives a BKEK from the secret master key).
 *          This BKEK is not the same used during normal blob encapsulation.
 *
 * @param[out] outkey  Output key generated
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 * @retval TEE_ERROR_GENERIC           Generic error
 */
static TEE_Result caam_master_key_verif(struct drvcrypt_buf *outkey)
{
#ifdef CFG_PHYS_64BIT
#define BLOB_MASTER_KEY_VERIF	9
#else
#define BLOB_MASTER_KEY_VERIF	7
#endif

	TEE_Result ret = TEE_ERROR_GENERIC;
	enum CAAM_Status retstatus;

	paddr_t paddr_keymod;
	uint8_t keymod_buf[BLOB_KEY_MODIFIER_SIZE] = {0};

	struct caambuf outkey_align = {0};
	int            realloc = 0;

	struct jr_jobctx jobctx = {0};
	descPointer_t    desc;

	/* Check if parameters are correct */
	if (!outkey)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!outkey->data)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Get the physical address of the key modifier */
	paddr_keymod = virt_to_phys(keymod_buf);
	if (!paddr_keymod)
		return TEE_ERROR_GENERIC;

	/* Realloc the outkey if not aligned or too small */
	realloc = caam_realloc_align(outkey->data, &outkey_align,
				BLOB_BKEK_SIZE);
	if (realloc == (-1)) {
		BLOB_TRACE("Output key reallocation error");
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	/* Allocate the job descriptor */
	desc = caam_alloc_desc(BLOB_MASTER_KEY_VERIF);
	if (!desc) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto exit_masterkey;
	}

	/*
	 * Create the Master Key Verification descriptor
	 */
	desc_init(desc);
	desc_add_word(desc, DESC_HEADER(0));

	/* Load the key modifier */
	desc_add_word(desc, LD_NOIMM(CLASS_2, REG_KEY, BLOB_KEY_MODIFIER_SIZE));
	desc_add_ptr(desc, paddr_keymod);

	/* Output key storage */
	desc_add_word(desc, SEQ_OUT_PTR(BLOB_BKEK_SIZE));
	desc_add_ptr(desc, outkey_align.paddr);

	/* Blob Master key verification operation */
	desc_add_word(desc, BLOB_MSTR_KEY);

	BLOB_DUMPDESC(desc);

	cache_operation(TEE_CACHECLEAN, keymod_buf, BLOB_KEY_MODIFIER_SIZE);
	cache_operation(TEE_CACHEFLUSH, outkey_align.data, outkey_align.length);

	jobctx.desc = desc;
	retstatus = caam_jr_enqueue(&jobctx, NULL);

	if (retstatus == CAAM_NO_ERROR) {
		cache_operation(TEE_CACHEINVALIDATE, outkey_align.data,
				outkey_align.length);
		BLOB_DUMPBUF("Master Key", outkey_align.data,
				outkey_align.length);

		if (realloc == 1)
			memcpy(outkey->data, outkey_align.data,
				MIN(outkey_align.length, outkey->length));

		ret = TEE_SUCCESS;
	} else {
		BLOB_TRACE("CAAM Status 0x%08"PRIx32"", jobctx.status);
		ret = job_status_to_tee_result(jobctx.status);
	}

exit_masterkey:
	caam_free_desc(&desc);
	if (realloc == 1)
		caam_free_buf(&outkey_align);

	return ret;
}

/**
 * @brief   Registration of the HUK Driver
 */
struct drvcrypt_huk driver_huk = {
	.generate_huk = &caam_master_key_verif,
};

/**
 * @brief   Initialize the HUK module
 *
 * @param[in] ctrl_addr   Controller base address
 *
 * @retval  CAAM_NO_ERROR    Success
 * @retval  CAAM_FAILURE     An error occurred
 * @retval  CAAM_OUT_MEMORY  Out of memory
 */
enum CAAM_Status caam_huk_init(vaddr_t ctrl_addr __unused)
{
	enum CAAM_Status retstatus = CAAM_FAILURE;

	if (drvcrypt_register(CRYPTO_HUK, &driver_huk) == 0)
		retstatus = CAAM_NO_ERROR;

	return retstatus;
}
