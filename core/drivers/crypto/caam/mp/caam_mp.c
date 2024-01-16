// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2018-2021, 2023 NXP
 */
#include <caam_hal_ctrl.h>
#include <caam_jr.h>
#include <caam_mp.h>
#include <caam_status.h>
#include <caam_utils_mem.h>
#include <caam_utils_status.h>
#include <drivers/caam_extension.h>
#include <kernel/pm.h>
#include <mm/core_memprot.h>
#include <string.h>
#include <tee/cache.h>
#include <tee_api_types.h>
#include <utee_defines.h>

#define MP_SIGN_MAX_MSG_SIZE (4 * 1024)

#ifdef CFG_PHYS_64BIT
#define MP_PRIV_DESC_ENTRIES 7
#define MP_PUB_DESC_ENTRIES  7
#define MP_SIGN_DESC_ENTRIES 13
#else
#define MP_PRIV_DESC_ENTRIES 6
#define MP_PUB_DESC_ENTRIES  6
#define MP_SIGN_DESC_ENTRIES 9
#endif

/*
 * MP module private data
 */
static struct mp_privdata {
	uint8_t curve;		    /* Protocol Data Block curve selection */
	uint8_t sec_size;	    /* Security key size in bytes */
	vaddr_t ctrl_addr;	    /* Base address of the controller */
	enum caam_status mp_status; /* Indicate the MP status */
} mp_privdata;

/*
 * Generate manufacturing private key.
 * The ECDSA private key is securely stored in the MPPKR.
 * This register is locked to prevent reading or writing.
 *
 * @passphrase	Passphrase
 * @len		Passphrase length
 */
static enum caam_status do_mppriv_gen(const char *passphrase, size_t len)
{
	enum caam_status ret = CAAM_FAILURE;
	struct caam_jobctx jobctx = { };
	uint32_t *desc = NULL;
	uint32_t desclen = 0;

	MP_TRACE("MP private key generation");

	assert(passphrase && len);

	desc = caam_calloc_desc(MP_PRIV_DESC_ENTRIES);
	if (!desc)
		return CAAM_OUT_MEMORY;

	caam_desc_init(desc);
	caam_desc_add_word(desc, DESC_HEADER(0));
	caam_desc_add_word(desc, PROT_MP_CURVE(mp_privdata.curve));
	caam_desc_add_ptr(desc, virt_to_phys((void *)passphrase));
	caam_desc_add_word(desc, len);
	caam_desc_add_word(desc, MPPRIVK);

	desclen = caam_desc_get_len(desc);
	caam_desc_update_hdr(desc, DESC_HEADER_IDX(desclen, desclen - 1));

	MP_DUMPDESC(desc);

	cache_operation(TEE_CACHECLEAN, (void *)passphrase, len);

	jobctx.desc = desc;
	ret = caam_jr_enqueue(&jobctx, NULL);

	if (ret != CAAM_NO_ERROR) {
		MP_TRACE("CAAM Status 0x%08" PRIx32, jobctx.status);
		ret = CAAM_NOT_SUPPORTED;
	}

	caam_free_desc(&desc);
	return ret;
}

TEE_Result caam_mp_export_mpmr(uint8_t *mpmr, size_t *size)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	struct caambuf caam_mpmr = {
		.data = mpmr,
		.length = *size,
	};

	MP_TRACE("Get MP message");

	ret = caam_hal_ctrl_read_mpmr(mp_privdata.ctrl_addr, &caam_mpmr);
	*size = caam_mpmr.length;

	return ret;
}

TEE_Result caam_mp_export_publickey(uint8_t *pubkey, size_t *size)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	enum caam_status retstatus = CAAM_FAILURE;
	struct caam_jobctx jobctx = { };
	struct caamdmaobj reskey = { };
	uint32_t pdb_sgt_flag = 0;
	uint32_t desclen = 0;
	uint32_t *desc = NULL;

	/* Check if MP is operational */
	if (mp_privdata.mp_status != CAAM_NO_ERROR)
		return caam_status_to_tee_result(mp_privdata.mp_status);

	if (!pubkey || !size)
		return TEE_ERROR_BAD_PARAMETERS;

	/* The public key size is twice the private key size */
	if (*size < 2 * mp_privdata.sec_size) {
		*size = 2 * mp_privdata.sec_size;
		return TEE_ERROR_SHORT_BUFFER;
	}

	ret = caam_dmaobj_output_sgtbuf(&reskey, pubkey, *size,
					2 * mp_privdata.sec_size);
	if (ret)
		return ret;

	if (reskey.sgtbuf.sgt_type)
		pdb_sgt_flag = PROT_MP_PUBK_SGT;

	desc = caam_calloc_desc(MP_PUB_DESC_ENTRIES);
	if (!desc) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	caam_desc_init(desc);
	caam_desc_add_word(desc, DESC_HEADER(0));
	caam_desc_add_word(desc,
			   PROT_MP_CURVE(mp_privdata.curve) | pdb_sgt_flag);
	caam_desc_add_ptr(desc, reskey.sgtbuf.paddr);
	caam_desc_add_word(desc, reskey.sgtbuf.length);
	caam_desc_add_word(desc, MPPUBK);

	desclen = caam_desc_get_len(desc);
	caam_desc_update_hdr(desc, DESC_HEADER_IDX(desclen, desclen - 1));

	MP_DUMPDESC(desc);

	caam_dmaobj_cache_push(&reskey);

	jobctx.desc = desc;
	retstatus = caam_jr_enqueue(&jobctx, NULL);

	if (retstatus == CAAM_NO_ERROR) {
		MP_TRACE("MP Public Key generated");
		reskey.orig.length = 2 * mp_privdata.sec_size;
		*size = caam_dmaobj_copy_to_orig(&reskey);

		MP_DUMPBUF("MP PubKey", pubkey, *size);

		ret = caam_status_to_tee_result(retstatus);
	} else {
		MP_TRACE("CAAM Status 0x%08" PRIx32, jobctx.status);
		ret = job_status_to_tee_result(jobctx.status);
	}

out:
	caam_dmaobj_free(&reskey);
	caam_free_desc(&desc);

	return ret;
}

TEE_Result caam_mp_sign(uint8_t *msg, size_t *msg_size, uint8_t *sig,
			size_t *sig_size)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	enum caam_status retstatus = CAAM_FAILURE;
	struct caam_jobctx jobctx = { };
	struct caamdmaobj msg_input = { };
	struct caamdmaobj sign_c = { };
	struct caamdmaobj sign_d = { };
	struct caambuf hash = { };
	uint32_t *desc = NULL;
	uint32_t desclen = 0;
	uint32_t pdb_sgt_flags = 0;
	uint8_t *aligned_msg = NULL;
	size_t sign_len = 0;

	MP_TRACE("MP sign operation");

	/* Check if MP is operational */
	if (mp_privdata.mp_status != CAAM_NO_ERROR)
		return caam_status_to_tee_result(mp_privdata.mp_status);

	if (!msg || !msg_size || !sig || !sig_size)
		return TEE_ERROR_BAD_PARAMETERS;

	if (*sig_size < 2 * mp_privdata.sec_size) {
		*sig_size = 2 * mp_privdata.sec_size;
		return TEE_ERROR_SHORT_BUFFER;
	}

	if (*msg_size > MP_SIGN_MAX_MSG_SIZE)
		return TEE_ERROR_EXCESS_DATA;

	/* Re-allocate the message to a cache-aligned buffer */
	aligned_msg = caam_alloc(*msg_size);
	if (!aligned_msg) {
		MP_TRACE("Message reallocation error");
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto exit_mpsign;
	}
	memcpy(aligned_msg, msg, *msg_size);

	/*
	 * Allocate the hash buffer of the Message + MPMR payload
	 * Note: Hash is not retrieve, hence no need to do cache
	 * maintenance
	 */
	retstatus = caam_alloc_align_buf(&hash, TEE_MAX_HASH_SIZE);
	if (retstatus != CAAM_NO_ERROR) {
		MP_TRACE("Hash allocation error");
		ret = caam_status_to_tee_result(retstatus);
		goto exit_mpsign;
	}

	/*
	 * Re-allocate the signature result buffer with a maximum size
	 * of the roundup to 16 bytes of the secure size in bytes if
	 * the signature buffer is not aligned or too short.
	 *
	 *  - 1st Part: size_sec
	 *  - 2nd Part: size_sec roundup to 16 bytes
	 */
	sign_len = ROUNDUP(mp_privdata.sec_size, 16) + mp_privdata.sec_size;

	ret = caam_dmaobj_output_sgtbuf(&sign_c, sig, *sig_size, sign_len);
	if (ret)
		goto exit_mpsign;

	if (sign_c.sgtbuf.sgt_type)
		pdb_sgt_flags |= PDB_SGT_MP_SIGN_C;

	/* Prepare the 2nd Part of the signature. Derived from sign_c */
	ret = caam_dmaobj_derive_sgtbuf(&sign_d, &sign_c, mp_privdata.sec_size,
					ROUNDUP(mp_privdata.sec_size, 16));
	if (ret)
		goto exit_mpsign;

	if (sign_d.sgtbuf.sgt_type)
		pdb_sgt_flags |= PDB_SGT_MP_SIGN_D;

	ret = caam_dmaobj_input_sgtbuf(&msg_input, aligned_msg, *msg_size);
	if (ret)
		goto exit_mpsign;

	if (msg_input.sgtbuf.sgt_type)
		pdb_sgt_flags |= PDB_SGT_MP_SIGN_MSG;

	desc = caam_calloc_desc(MP_SIGN_DESC_ENTRIES);
	if (!desc) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto exit_mpsign;
	}

	caam_desc_init(desc);
	caam_desc_add_word(desc, DESC_HEADER(0));
	caam_desc_add_word(desc,
			   PROT_MP_CURVE(mp_privdata.curve) | pdb_sgt_flags);
	caam_desc_add_ptr(desc, msg_input.sgtbuf.paddr);
	caam_desc_add_ptr(desc, hash.paddr);
	caam_desc_add_ptr(desc, sign_c.sgtbuf.paddr);
	caam_desc_add_ptr(desc, sign_d.sgtbuf.paddr);
	caam_desc_add_word(desc, msg_input.sgtbuf.length);
	caam_desc_add_word(desc, MPSIGN_OP);

	desclen = caam_desc_get_len(desc);
	caam_desc_update_hdr(desc, DESC_HEADER_IDX(desclen, desclen - 1));

	MP_DUMPDESC(desc);

	caam_dmaobj_cache_push(&msg_input);
	caam_dmaobj_cache_push(&sign_c);

	jobctx.desc = desc;
	retstatus = caam_jr_enqueue(&jobctx, NULL);

	if (retstatus == CAAM_NO_ERROR) {
		sign_c.orig.length = 2 * mp_privdata.sec_size;
		*sig_size = caam_dmaobj_copy_to_orig(&sign_c);

		MP_DUMPBUF("MP Signature", sdata->signature.data,
			   sdata->signature.length);

		ret = caam_status_to_tee_result(retstatus);
	} else {
		MP_TRACE("CAAM Status 0x%08" PRIx32, jobctx.status);
		ret = job_status_to_tee_result(jobctx.status);
	}

exit_mpsign:
	caam_free(aligned_msg);
	caam_free_buf(&hash);
	caam_free_desc(&desc);
	caam_dmaobj_free(&msg_input);
	caam_dmaobj_free(&sign_c);
	caam_dmaobj_free(&sign_d);

	return ret;
}

enum caam_status caam_mp_init(vaddr_t ctrl_addr)
{
	/*
	 * Manufacturing protection secret values for DSA key pair
	 * generation.
	 */
	static const char passphrase[] = "manufacturing protection";
	static const char mpmr_data[] = "value to fill the MPMR content";
	enum caam_status retstatus = CAAM_FAILURE;
	uint8_t curve = 0;
	uint8_t hash_limit = 0;

	struct caambuf msg_mpmr = {
		.data = (uint8_t *)mpmr_data,
		.length = strlen(mpmr_data)
	};

	mp_privdata.ctrl_addr = ctrl_addr;
	mp_privdata.mp_status = CAAM_NOT_INIT;

	curve = caam_hal_ctrl_get_mpcurve(ctrl_addr);

	if (curve == UINT8_MAX) {
		mp_privdata.mp_status = CAAM_NOT_SUPPORTED;
		return mp_privdata.mp_status;
	}

	if (caam_hal_ctrl_is_mp_set(ctrl_addr)) {
		mp_privdata.mp_status = CAAM_NO_ERROR;
		return CAAM_NO_ERROR;
	}

	if (!curve) {
		/* Get the device HASH Limit to select the MP Curve */
		hash_limit = caam_hal_ctrl_hash_limit(ctrl_addr);

		switch (hash_limit) {
		case TEE_MAIN_ALGO_SHA256:
			mp_privdata.curve = PDB_MP_CSEL_P256;
			mp_privdata.sec_size = 32;
			break;
		case TEE_MAIN_ALGO_SHA512:
			mp_privdata.curve = PDB_MP_CSEL_P521;
			mp_privdata.sec_size = 66;
			break;
		default:
			MP_TRACE("This curve doesn't exist");
			return CAAM_FAILURE;
		}

		MP_TRACE("Generating MP Private key");
		retstatus = do_mppriv_gen(passphrase, strlen(passphrase));

		if (retstatus != CAAM_NO_ERROR) {
			MP_TRACE("do_mppriv_gen failed!");
			return retstatus;
		}
	} else {
		/* MP Curve is already programmed. Set the right key size */
		mp_privdata.curve = curve;

		switch (curve) {
		case PDB_MP_CSEL_P256:
			mp_privdata.sec_size = 32;
			break;
		case PDB_MP_CSEL_P521:
			mp_privdata.sec_size = 66;
			break;
		default:
			MP_TRACE("This curve is not supported");
			return CAAM_FAILURE;
		}
	}

	/* Fill the MPMR content then lock it */
	caam_hal_ctrl_fill_mpmr(ctrl_addr, &msg_mpmr);

	mp_privdata.mp_status = CAAM_NO_ERROR;

	return CAAM_NO_ERROR;
}

enum caam_status caam_mp_resume(uint32_t pm_hint)
{
	if (pm_hint == PM_HINT_CONTEXT_STATE)
		return caam_mp_init(mp_privdata.ctrl_addr);

	return CAAM_NO_ERROR;
}
