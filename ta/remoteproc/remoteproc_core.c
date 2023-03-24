// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2023, STMicroelectronics
 */

#include <elf_parser.h>
#include <remoteproc_pta.h>
#include <string.h>
#include <sys/queue.h>
#include <ta_remoteproc.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <types_ext.h>
#include <utee_defines.h>

/*
 * The remoteproc Trusted Application is in charge of authenticating, loading
 * images signed by the scripts/sign_rproc_fw.py. The TA is also in charge of
 * starting and stopping the remote processor.
 * The structure of the signed image is:
 *
 *                   -----+-------------+
 *                  /     |    Magic    |  32-bit word, magic value equal to
 *                 /      +-------------+  0x3543A468
 *                /       +-------------+
 *               /        |   version   |  32-bit word, version of the format
 *              /         +-------------+
 * +-----------+          +-------------+
 * |   Header  |          |  TLV size   |  32-bit word, size of the TLV
 * +-----------+          +-------------+  (aligned on 64-bit), in bytes.
 *              \         +-------------+
 *               \        |  sign size  |  32-bit word, size of the signature
 *                \       +-------------+  (aligned on 64-bit), in bytes.
 *                 \      +-------------+
 *                  \     | images size |  32-bit word, size of the images to
 *                   -----+-------------+  load (aligned on 64-bit), in bytes.
 *
 *                        +-------------+  Information used to authenticate the
 *                        |     TLV     |  images and boot the remote processor,
 *                        |             |  stored in Type-Length-Value format.
 *                        +-------------+  'Type' and 'Length' are 32-bit words.
 *
 *                        +-------------+
 *                        | Signature   |   Signature of the header and the TLV.
 *                        +-------------+
 *
 *                        +-------------+
 *                        |   Firmware  |
 *                        |    image 1  |
 *                        +-------------+
 *                               ...
 *                        +-------------+
 *                        |   Firmware  |
 *                        |    image n  |
 *                        +-------------+
 */

/* Firmware state */
enum remoteproc_state {
	REMOTEPROC_OFF,
	REMOTEPROC_LOADED,
	REMOTEPROC_STARTED,
};

#define RPROC_HDR_MAGIC		0x3543A468 /* random value */
#define HEADER_VERSION		1

/* Supported signature algorithm */
enum remoteproc_sign_type {
	RPROC_RSASSA_PKCS1_v1_5_SHA256 = 1,
	RPROC_ECDSA_SHA256 = 2,
};

enum remoteproc_img_type {
	REMOTEPROC_ELF_TYPE = 1,
	REMOTEPROC_INVALID_TYPE = 0xFF
};

/* remoteproc_tlv structure offsets */
#define RPROC_TLV_LENGTH_OF	U(0x04)
#define RPROC_TLV_VALUE_OF	U(0x08)

/* TLV types */
#define RPROC_TLV_SIGNTYPE	U(0x00000001)
#define RPROC_TLV_HASHTYPE	U(0x00000002)
#define RPROC_TLV_NUM_IMG	U(0x00000003)
#define RPROC_TLV_IMGTYPE	U(0x00000004)
#define RPROC_TLV_IMGSIZE	U(0x00000005)
#define RPROC_TLV_HASHTABLE	U(0x00000010)
#define RPROC_TLV_PKEYINFO	U(0x00000011)

#define RPROC_PLAT_TLV_TYPE_MIN	U(0x00010000)
#define RPROC_PLAT_TLV_TYPE_MAX	U(0x00020000)

#define RPROC_TLV_SIGNTYPE_LGTH U(1)

#define LE16_TO_CPU(x) ({ uint8_t *_x = x; ((_x)[1] << 8) | (_x)[0]; })
#define LE32_TO_CPU(x) ({ uint8_t *_x = x; ((_x)[3] << 24) | ((_x)[2] << 16) | \
					   ((_x)[1] << 8) | (_x)[0]; })

#define U64_ADD_TO_ALIGN(s) ({ size_t _s = s; (_s) + sizeof(uint64_t) - \
					     ((_s) % sizeof(uint64_t)); })
#define U64_ALIGN_SZ(x) ({ size_t _x = x; (_x) % (sizeof(uint64_t)) ? \
					  U64_ADD_TO_ALIGN(_x) : (_x); })

/*
 * struct remoteproc_tlv - Type-Length-Value structure
 * @type: type of data
 * @length: size of the data.
 * @value: pointer to the data.
 */
struct remoteproc_tlv {
	uint32_t type;
	uint32_t length;
	uint8_t value[];
};

/*
 * struct remoteproc_segment - program header with hash structure
 * @phdr: program header
 * @hash: hash associated to the program segment.
 */
struct remoteproc_segment {
	Elf32_Phdr phdr;
	uint8_t hash[TEE_SHA256_HASH_SIZE];
};

/*
 * struct remoteproc_fw_hdr - firmware header
 * @magic:        Magic number, must be equal to RPROC_HDR_MAGIC
 * @version:      Version of the header (must be 1)
 * @tlv_len:      Generic meta data chunk (TLV format)
 * @sign_len:     Signature chunk byte length
 * @img_len:      Firmware image chunk byte length
 */
struct remoteproc_fw_hdr {
	uint32_t magic;
	uint32_t version;
	uint32_t tlv_len;
	uint32_t sign_len;
	uint32_t img_len;
};

#define FW_TLV_PTR(img, hdr)  ((img) + sizeof(*(hdr)))
#define FW_SIGN_PTR(img, hdr) ({ struct remoteproc_fw_hdr *__hdr = hdr; \
				 FW_TLV_PTR((img), (__hdr)) +    \
				 U64_ALIGN_SZ(__hdr->tlv_len); })
#define FW_IMG_PTR(img, hdr)     ({ struct remoteproc_fw_hdr *___hdr = hdr; \
				 FW_SIGN_PTR((img), (___hdr)) +    \
				 U64_ALIGN_SZ(___hdr->sign_len); })
/*
 * struct remoteproc_sig_algo - signature algorithm information
 * @sign_type: Header signature type
 * @id:        Signature algorithm identifier TEE_ALG_*
 * @hash_len:  Signature hash length
 */
struct remoteproc_sig_algo {
	enum remoteproc_sign_type sign_type;
	uint32_t id;
	size_t hash_len;
};

/*
 * struct remoteproc_context - firmware context
 * @fw_id:       Unique Id of the firmware
 * @sec_cpy:     Location of a secure copy of the header, TLVs and signature
 * @tlvs:        Location of a secure copy of the firmware TLVs
 * @tlvs_sz:     Byte size of the firmware TLVs blob.
 * @fw_img:      Firmware image
 * @fw_img_sz:   Byte size of the firmware image
 * @hash_table:  Location of a copy of the segment's hash table
 * @nb_segment:  number of segment to load
 * @state:       Remote-processor state
 * @hw_fmt:      Image format capabilities of the remoteproc PTA
 * @hw_img_prot: Image protection capabilities of the remoteproc PTA
 * @link:        Linked list element
 */
struct remoteproc_context {
	uint32_t fw_id;
	uint8_t *sec_cpy;
	uint8_t *tlvs;
	size_t tlvs_sz;
	uint8_t *fw_img;
	size_t fw_img_sz;
	struct remoteproc_segment *hash_table;
	uint32_t nb_segment;
	enum remoteproc_state state;
	uint32_t hw_fmt;
	uint32_t hw_img_prot;
	TAILQ_ENTRY(remoteproc_context) link;
};

TAILQ_HEAD(remoteproc_firmware_head, remoteproc_context);

static struct remoteproc_firmware_head firmware_head =
	TAILQ_HEAD_INITIALIZER(firmware_head);

static const struct remoteproc_sig_algo rproc_ta_sign_algo[] = {
	{
		.sign_type = RPROC_RSASSA_PKCS1_v1_5_SHA256,
		.id = TEE_ALG_RSASSA_PKCS1_V1_5_SHA256,
		.hash_len = TEE_SHA256_HASH_SIZE,
	},
	{
		.sign_type = RPROC_ECDSA_SHA256,
		.id = TEE_ALG_ECDSA_P256,
		.hash_len = TEE_SHA256_HASH_SIZE,
	},
};

static size_t session_refcount;
static TEE_TASessionHandle pta_session;

static void remoteproc_header_dump(struct remoteproc_fw_hdr __maybe_unused *hdr)
{
	DMSG("magic :\t%#"PRIx32, hdr->magic);
	DMSG("version :\t%#"PRIx32, hdr->version);
	DMSG("tlv_len :\t%#"PRIx32, hdr->tlv_len);
	DMSG("sign_len :\t%#"PRIx32, hdr->sign_len);
	DMSG("img_len :\t%#"PRIx32, hdr->img_len);
}

static TEE_Result
remoteproc_get_tlv(void *tlv_chunk, size_t tlv_size, uint16_t type,
		   uint8_t **value, size_t *length)
{
	uint8_t *p_tlv = (uint8_t *)tlv_chunk;
	uint8_t *p_end_tlv = p_tlv + tlv_size;
	uint32_t tlv_type = 0;
	uint32_t tlv_length = 0;

	*value = NULL;
	*length = 0;

	/* Parse the tlv area */
	while (p_tlv < p_end_tlv) {
		tlv_type = LE32_TO_CPU(p_tlv);
		tlv_length = LE32_TO_CPU(&p_tlv[RPROC_TLV_LENGTH_OF]);
		if (tlv_type == type) {
			/* The specified TLV has been found */
			DMSG("TLV type %#"PRIx32" found, size %#"PRIx32,
			     type, tlv_length);
			*value = &p_tlv[RPROC_TLV_VALUE_OF];
			*length = tlv_length;
			if (tlv_length)
				return TEE_SUCCESS;
			else
				return TEE_ERROR_NO_DATA;
		}
		p_tlv += U64_ALIGN_SZ(sizeof(struct remoteproc_tlv) +
				      tlv_length);
	}

	return TEE_ERROR_NO_DATA;
}

static struct remoteproc_context *remoteproc_find_firmware(uint32_t fw_id)
{
	struct remoteproc_context *ctx = NULL;

	TAILQ_FOREACH(ctx, &firmware_head, link)
		if (ctx->fw_id == fw_id)
			return ctx;

	return NULL;
}

static struct remoteproc_context *remoteproc_add_firmware(uint32_t fw_id)
{
	struct remoteproc_context *ctx = NULL;

	ctx = TEE_Malloc(sizeof(*ctx), TEE_MALLOC_FILL_ZERO);
	if (!ctx)
		return NULL;

	ctx->fw_id = fw_id;

	TAILQ_INSERT_TAIL(&firmware_head, ctx, link);

	return ctx;
}

static const struct remoteproc_sig_algo *remoteproc_get_algo(uint32_t sign_type)
{
	unsigned int i = 0;

	for (i = 0; i < ARRAY_SIZE(rproc_ta_sign_algo); i++)
		if (sign_type == rproc_ta_sign_algo[i].sign_type)
			return &rproc_ta_sign_algo[i];

	return NULL;
}

static TEE_Result remoteproc_pta_verify(struct remoteproc_context *ctx,
					const struct remoteproc_sig_algo *algo,
					uint8_t *hash, uint32_t hash_len)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct remoteproc_fw_hdr *hdr = (void *)ctx->sec_cpy;
	struct rproc_pta_key_info *keyinfo = NULL;
	uint32_t param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
					       TEE_PARAM_TYPE_MEMREF_INPUT,
					       TEE_PARAM_TYPE_MEMREF_INPUT,
					       TEE_PARAM_TYPE_MEMREF_INPUT);
	TEE_Param params[TEE_NUM_PARAMS] = { };
	size_t length = 0;
	uint8_t *tlv_keyinfo = NULL;
	uint8_t *sign = NULL;

	res = remoteproc_get_tlv(ctx->tlvs, hdr->tlv_len,
				 RPROC_TLV_PKEYINFO, &tlv_keyinfo,
				 &length);
	if (res != TEE_SUCCESS && res != TEE_ERROR_NO_DATA)
		return res;

	keyinfo = TEE_Malloc(sizeof(*keyinfo) + length, TEE_MALLOC_FILL_ZERO);
	if (!keyinfo)
		return TEE_ERROR_OUT_OF_MEMORY;

	keyinfo->algo = algo->id;
	keyinfo->info_size = length;
	memcpy(keyinfo->info, tlv_keyinfo, length);

	sign = FW_SIGN_PTR(ctx->sec_cpy, hdr);

	params[0].value.a = ctx->fw_id;
	params[1].memref.buffer = keyinfo;
	params[1].memref.size = rproc_pta_keyinfo_size(keyinfo);
	params[2].memref.buffer = hash;
	params[2].memref.size = hash_len;
	params[3].memref.buffer = sign;
	params[3].memref.size = hdr->sign_len;

	res = TEE_InvokeTACommand(pta_session, TEE_TIMEOUT_INFINITE,
				  PTA_RPROC_VERIFY_DIGEST,
				  param_types, params, NULL);
	if (res != TEE_SUCCESS)
		EMSG("Failed to verify signature, res = %#"PRIx32, res);

	TEE_Free(keyinfo);

	return res;
}

static TEE_Result
remoteproc_save_fw_header_and_tlvs(struct remoteproc_context *ctx,
				   void *fw_orig, uint32_t fw_orig_size)
{
	struct remoteproc_fw_hdr *hdr = fw_orig;
	uint32_t length = 0;

	length = sizeof(*hdr) + hdr->tlv_len + hdr->sign_len;

	if (fw_orig_size <= length || !hdr->sign_len || !hdr->tlv_len)
		return TEE_ERROR_BAD_PARAMETERS;

	remoteproc_header_dump(hdr);

	/* Copy the header, the TLVs and the signature in secure memory */
	ctx->sec_cpy = TEE_Malloc(length, TEE_MALLOC_FILL_ZERO);
	if (!ctx->sec_cpy)
		return TEE_ERROR_OUT_OF_MEMORY;

	memcpy(ctx->sec_cpy, fw_orig, length);

	return TEE_SUCCESS;
}

static TEE_Result remoteproc_verify_signature(struct remoteproc_context *ctx)
{
	TEE_OperationHandle op = TEE_HANDLE_NULL;
	struct remoteproc_fw_hdr *hdr = (void *)ctx->sec_cpy;
	const struct remoteproc_sig_algo *algo = NULL;
	TEE_Result res = TEE_ERROR_GENERIC;
	uint8_t *tlv_sign_algo = NULL;
	size_t length = 0;
	uint8_t *hash = NULL;
	size_t hash_len = 0;

	/* Get the algo type from TLV data */
	res = remoteproc_get_tlv(ctx->tlvs, hdr->tlv_len, RPROC_TLV_SIGNTYPE,
				 &tlv_sign_algo, &length);

	if (res != TEE_SUCCESS || length != RPROC_TLV_SIGNTYPE_LGTH)
		return TEE_ERROR_BAD_PARAMETERS;

	algo = remoteproc_get_algo(*tlv_sign_algo);
	if (!algo) {
		EMSG("Unsupported signature type %d", *tlv_sign_algo);
		return TEE_ERROR_NOT_SUPPORTED;
	}

	/* Compute the header and TLVs hashes */
	hash_len = algo->hash_len;
	hash = TEE_Malloc(hash_len, TEE_MALLOC_FILL_ZERO);
	if (!hash)
		return TEE_ERROR_OUT_OF_MEMORY;

	res = TEE_AllocateOperation(&op, TEE_ALG_SHA256, TEE_MODE_DIGEST, 0);
	if (res != TEE_SUCCESS)
		goto free_hash;

	TEE_DigestUpdate(op, hdr, sizeof(*hdr));
	res = TEE_DigestDoFinal(op, ctx->tlvs, U64_ALIGN_SZ(hdr->tlv_len),
				hash, &hash_len);

	if (res != TEE_SUCCESS)
		goto out;

	/*
	 * This implementation could be enhanced by providing alternative to
	 * verify the signature in the TA. This could be done for instance by
	 * getting the key object from secure storage.
	 */

	/* By default ask the pta to verify the signature. */
	res = remoteproc_pta_verify(ctx, algo, hash, hash_len);

out:
	TEE_FreeOperation(op);
free_hash:
	TEE_Free(hash);

	return res;
}

static TEE_Result remoteproc_verify_header(struct remoteproc_context *ctx,
					   uint32_t fw_orig_size)
{
	struct remoteproc_fw_hdr *hdr = (void *)ctx->sec_cpy;
	uint32_t size = 0;

	if (hdr->magic != RPROC_HDR_MAGIC)
		return TEE_ERROR_BAD_PARAMETERS;

	if (hdr->version != HEADER_VERSION)
		return TEE_ERROR_BAD_PARAMETERS;

	/*
	 * The offsets are aligned to 64 bits format. While the length of each
	 * chunks are the effective length, excluding the alignment padding
	 * bytes.
	 */
	if (ADD_OVERFLOW(sizeof(*hdr), U64_ALIGN_SZ(hdr->sign_len), &size) ||
	    ADD_OVERFLOW(size, U64_ALIGN_SZ(hdr->img_len), &size) ||
	    ADD_OVERFLOW(size, U64_ALIGN_SZ(hdr->tlv_len), &size) ||
	    fw_orig_size != size)
		return TEE_ERROR_BAD_PARAMETERS;

	return TEE_SUCCESS;
}

static TEE_Result get_rproc_pta_capabilities(struct remoteproc_context *ctx)
{
	uint32_t param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
					       TEE_PARAM_TYPE_VALUE_OUTPUT,
					       TEE_PARAM_TYPE_VALUE_OUTPUT,
					       TEE_PARAM_TYPE_NONE);
	TEE_Param params[TEE_NUM_PARAMS] = { };
	TEE_Result res = TEE_ERROR_GENERIC;

	params[0].value.a = ctx->fw_id;

	res = TEE_InvokeTACommand(pta_session, TEE_TIMEOUT_INFINITE,
				  PTA_RPROC_HW_CAPABILITIES,
				  param_types, params, NULL);
	if (res)
		return res;

	ctx->hw_fmt = params[1].value.a;
	ctx->hw_img_prot = params[2].value.a;

	return TEE_SUCCESS;
}

static TEE_Result remoteproc_verify_firmware(struct remoteproc_context *ctx,
					     uint8_t *fw_orig,
					     uint32_t fw_orig_size)
{
	struct remoteproc_fw_hdr *hdr = NULL;
	TEE_Result res = TEE_ERROR_GENERIC;

	res = get_rproc_pta_capabilities(ctx);
	if (res)
		return res;

	/* Secure the firmware image depending on strategy */
	if (!(ctx->hw_img_prot & PTA_RPROC_FW_WITH_HASH_TABLE) ||
	    ctx->hw_fmt != PTA_RPROC_ELF_FMT) {
		/*
		 * Only hash table for ELF format support implemented
		 * in a first step.
		 */
		return TEE_ERROR_NOT_IMPLEMENTED;
	}

	res = remoteproc_save_fw_header_and_tlvs(ctx, fw_orig, fw_orig_size);
	if (res)
		return res;

	res = remoteproc_verify_header(ctx, fw_orig_size);
	if (res)
		goto free_sec_cpy;

	hdr = (void *)ctx->sec_cpy;
	ctx->tlvs_sz = hdr->tlv_len;
	ctx->tlvs = FW_TLV_PTR(ctx->sec_cpy, hdr);

	res = remoteproc_verify_signature(ctx);
	if (res)
		goto free_sec_cpy;

	/* Store location of the loadable binary in non-secure memory */
	ctx->fw_img_sz = hdr->img_len;
	ctx->fw_img = FW_IMG_PTR(fw_orig, hdr);

	DMSG("Firmware images addr: %p size: %zu", ctx->fw_img,
	     ctx->fw_img_sz);

	return res;

free_sec_cpy:
	TEE_Free(ctx->sec_cpy);

	return res;
}

static TEE_Result get_hash_table(struct remoteproc_context *ctx)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint8_t *tlv_hash = NULL;
	struct remoteproc_segment *hash_table = NULL;
	size_t length = 0;

	/* Get the segment's hash table from TLV data */
	res = remoteproc_get_tlv(ctx->tlvs, ctx->tlvs_sz, RPROC_TLV_HASHTABLE,
				 &tlv_hash, &length);
	if (res || (length % sizeof(struct remoteproc_segment)))
		return res;

	/* We can not ensure that tlv_hash is memory aligned so make a copy */
	hash_table = TEE_Malloc(length, TEE_MALLOC_FILL_ZERO);
	if (!hash_table)
		return TEE_ERROR_OUT_OF_MEMORY;

	memcpy(hash_table, tlv_hash, length);

	ctx->hash_table = hash_table;
	ctx->nb_segment = length / sizeof(struct remoteproc_segment);

	return TEE_SUCCESS;
}

static TEE_Result get_tlv_images_type(struct remoteproc_context *ctx,
				      uint8_t num_img, uint8_t idx,
				      uint8_t *img_type)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint8_t *tlv_value = NULL;
	size_t length = 0;

	/* Get the type of the image to load, from TLV data */
	res = remoteproc_get_tlv(ctx->tlvs, ctx->tlvs_sz, RPROC_TLV_IMGTYPE,
				 &tlv_value, &length);
	if (res || length != (sizeof(*img_type) * num_img))
		return res;

	*img_type = tlv_value[idx];

	return TEE_SUCCESS;
}

static TEE_Result get_tlv_images_size(struct remoteproc_context *ctx,
				      uint8_t num_img, uint8_t idx,
				      uint32_t *img_size)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint8_t *tlv_value = NULL;
	size_t length = 0;

	/* Get the size of the image to load, from TLV data */
	res = remoteproc_get_tlv(ctx->tlvs, ctx->tlvs_sz, RPROC_TLV_IMGSIZE,
				 &tlv_value, &length);
	if (res || length != (sizeof(*img_size) * num_img))
		return res;

	*img_size = LE32_TO_CPU(&tlv_value[sizeof(*img_size) * idx]);

	return TEE_SUCCESS;
}

static TEE_Result get_segment_hash(struct remoteproc_context *ctx, uint8_t *src,
				   uint32_t size, uint32_t da,
				   uint32_t mem_size, uint8_t **hash)
{
	struct remoteproc_segment *peh = NULL;
	unsigned int i = 0;
	unsigned int nb_entry = ctx->nb_segment;

	peh = (void *)(ctx->hash_table);

	for (i = 0; i < nb_entry; peh++, i++) {
		if (peh->phdr.p_paddr != da)
			continue;

		/*
		 * Segment is read from a non secure memory. Crosscheck it using
		 * the hash table to verify that the segment has not been
		 * corrupted.
		 */
		if (peh->phdr.p_type != PT_LOAD)
			return TEE_ERROR_BAD_PARAMETERS;

		if (peh->phdr.p_filesz != size || peh->phdr.p_memsz != mem_size)
			return TEE_ERROR_BAD_PARAMETERS;

		if (src < ctx->fw_img ||
		    (src + peh->phdr.p_filesz) > (ctx->fw_img + ctx->fw_img_sz))
			return TEE_ERROR_BAD_PARAMETERS;

		*hash = peh->hash;

		return TEE_SUCCESS;
	}

	return TEE_ERROR_NO_DATA;
}

static TEE_Result remoteproc_load_segment(uint8_t *src, uint32_t size,
					  uint32_t da, uint32_t mem_size,
					  void *priv)
{
	struct remoteproc_context *ctx = priv;
	uint32_t param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
					       TEE_PARAM_TYPE_MEMREF_INPUT,
					       TEE_PARAM_TYPE_VALUE_INPUT,
					       TEE_PARAM_TYPE_MEMREF_INPUT);
	TEE_Param params[TEE_NUM_PARAMS] = { };
	TEE_Result res = TEE_ERROR_GENERIC;
	uint8_t *hash = NULL;

	/*
	 * Invoke platform remoteproc PTA to load the segment in remote
	 * processor memory which is not mapped in the TA space.
	 */

	DMSG("Load segment %#"PRIx32" size %"PRIu32" (%"PRIu32")", da, size,
	     mem_size);

	res = get_segment_hash(ctx, src, size, da, mem_size, &hash);
	if (res)
		return res;

	params[0].value.a = ctx->fw_id;
	params[1].memref.buffer = src;
	params[1].memref.size = size;
	params[2].value.a = da;
	params[3].memref.buffer = hash;
	params[3].memref.size = TEE_SHA256_HASH_SIZE;

	if (size) {
		res = TEE_InvokeTACommand(pta_session, TEE_TIMEOUT_INFINITE,
					  PTA_RPROC_LOAD_SEGMENT_SHA256,
					  param_types, params, NULL);
		if (res != TEE_SUCCESS) {
			EMSG("Fails to load segment, res = 0x%x", res);
			return res;
		}
	}

	/* Fill the rest of the memory with 0 */
	if (size < mem_size) {
		param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
					      TEE_PARAM_TYPE_VALUE_INPUT,
					      TEE_PARAM_TYPE_VALUE_INPUT,
					      TEE_PARAM_TYPE_VALUE_INPUT);
		params[1].value.a = da + size;
		params[2].value.a = mem_size - size;
		params[3].value.a = 0;

		res = TEE_InvokeTACommand(pta_session, TEE_TIMEOUT_INFINITE,
					  PTA_RPROC_SET_MEMORY,
					  param_types, params, NULL);
		if (res != TEE_SUCCESS)
			EMSG("Fails to clear segment, res = 0x%x", res);
	}

	return res;
}

static TEE_Result remoteproc_load_elf(struct remoteproc_context *ctx)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint8_t num_img = 0, i = 0;
	uint8_t img_type = REMOTEPROC_INVALID_TYPE;
	uint32_t img_size = 0;
	uint8_t *tlv = NULL;
	int32_t offset = 0;
	size_t length = 0;

	res = e32_parse_ehdr(ctx->fw_img, ctx->fw_img_sz);
	if (res) {
		EMSG("Failed to parse firmware, res = %#"PRIx32, res);
		return res;
	}

	res = get_hash_table(ctx);
	if (res)
		return res;

	/* Get the number of firmware images to load */

	res = remoteproc_get_tlv(ctx->tlvs, ctx->tlvs_sz, RPROC_TLV_NUM_IMG,
				 &tlv, &length);
	if (res)
		goto out;
	if (length != sizeof(uint8_t)) {
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}

	num_img = *tlv;
	if (!num_img) {
		res = TEE_ERROR_NO_DATA;
		goto out;
	}

	for (i = 0; i < num_img; i++) {
		res = get_tlv_images_type(ctx, num_img, i, &img_type);
		if (res)
			goto out;
		if (img_type != REMOTEPROC_ELF_TYPE) {
			res = TEE_ERROR_BAD_FORMAT;
			goto out;
		}

		res = get_tlv_images_size(ctx, num_img, i, &img_size);
		if (res)
			goto out;

		res = e32_parser_load_elf_image(ctx->fw_img + offset, img_size,
						remoteproc_load_segment, ctx);
		if (res)
			goto out;

		offset += img_size;
	}

out:
	/* Should we clean-up the memories in case of fail ? */
	TEE_Free(ctx->hash_table);

	return res;
}

static TEE_Result remoteproc_load_fw(uint32_t pt,
				     TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_MEMREF_INPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	struct remoteproc_context *ctx = NULL;
	uint32_t fw_id = params[0].value.a;
	TEE_Result res = TEE_ERROR_GENERIC;

	if (pt != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	ctx = remoteproc_find_firmware(fw_id);
	if (!ctx)
		ctx = remoteproc_add_firmware(fw_id);
	if (!ctx)
		return TEE_ERROR_OUT_OF_MEMORY;

	if (ctx->state != REMOTEPROC_OFF)
		return TEE_ERROR_BAD_STATE;

	if (!params[1].memref.buffer || !params[1].memref.size)
		return TEE_ERROR_BAD_PARAMETERS;

	DMSG("Got base addr: %p size %zx", params[1].memref.buffer,
	     params[1].memref.size);

	res = remoteproc_verify_firmware(ctx, params[1].memref.buffer,
					 params[1].memref.size);
	if (res) {
		EMSG("Can't Authenticate the firmware ID %d (res = %#"PRIx32")",
		     fw_id, res);
		goto out;
	}

	res = remoteproc_load_elf(ctx);
	if (res)
		goto out;

	ctx->state = REMOTEPROC_LOADED;

out:
	/* Clear reference to firmware image from shared memory */
	ctx->fw_img = NULL;
	ctx->fw_img_sz = 0;
	ctx->nb_segment = 0;

	/* Free allocated memories */
	TEE_Free(ctx->sec_cpy);

	return res;
}

TEE_Result TA_CreateEntryPoint(void)
{
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
}

/*
 * TA_OpenSessionEntryPoint: open a TA session associated to a firmware
 * to manage.
 *
 * [in] params[0].value.a:	unique 32bit identifier of the firmware
 */
TEE_Result TA_OpenSessionEntryPoint(uint32_t pt,
				    TEE_Param params[TEE_NUM_PARAMS],
				    void **sess __unused)
{
	static const TEE_UUID uuid = PTA_RPROC_UUID;
	TEE_Result res = TEE_ERROR_GENERIC;
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);

	if (pt != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!session_refcount) {
		res = TEE_OpenTASession(&uuid, TEE_TIMEOUT_INFINITE, pt, params,
					&pta_session, NULL);
		if (res)
			return res;
	}

	session_refcount++;

	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess __unused)
{
	session_refcount--;

	if (!session_refcount)
		TEE_CloseTASession(pta_session);
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess __unused, uint32_t cmd_id,
				      uint32_t pt,
				      TEE_Param params[TEE_NUM_PARAMS])
{
	switch (cmd_id) {
	case TA_RPROC_CMD_LOAD_FW:
		return remoteproc_load_fw(pt, params);
	case TA_RPROC_CMD_START_FW:
		return TEE_ERROR_NOT_IMPLEMENTED;
	case TA_RPROC_CMD_STOP_FW:
		return TEE_ERROR_NOT_IMPLEMENTED;
	case TA_RPROC_CMD_GET_RSC_TABLE:
		return TEE_ERROR_NOT_IMPLEMENTED;
	case TA_RPROC_CMD_GET_COREDUMP:
		return TEE_ERROR_NOT_IMPLEMENTED;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
