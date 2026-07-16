// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <elf32.h>
#include <pas_mbn_parser.h>
#include <pas_mbn_parser_priv.h>
#include <string.h>
#include <tee_internal_api.h>
#include <util.h>

/*
 * A UIE image-encryption parameter block, when present, follows the last cert
 * region in the hash segment. Its header begins with this little-endian magic.
 */
#define UIE_ENC_PARAM_MAGIC	0x514D5349	/* "ISMQ" */

uint32_t pas_mbn_read_u32(const uint8_t *p)
{
	uint32_t v = 0;

	memcpy(&v, p, sizeof(v));

	return v;
}

TEE_Result pas_mbn_locate(const uint8_t *md, size_t md_size,
			  const uint8_t **seg, size_t *seg_size,
			  size_t *preamble)
{
	const Elf32_Ehdr *ehdr = (const void *)md;
	const Elf32_Phdr *phdrs = NULL;
	size_t phtab_end = 0;
	size_t preamble_len = 0;

	if (md_size < sizeof(*ehdr))
		return TEE_ERROR_BAD_FORMAT;

	if (ehdr->e_ident[EI_MAG0] != ELFMAG0 ||
	    ehdr->e_ident[EI_MAG1] != ELFMAG1 ||
	    ehdr->e_ident[EI_MAG2] != ELFMAG2 ||
	    ehdr->e_ident[EI_MAG3] != ELFMAG3 ||
	    ehdr->e_ident[EI_CLASS] != ELFCLASS32)
		return TEE_ERROR_BAD_FORMAT;

	if (ehdr->e_phnum < 2 || !ehdr->e_phoff ||
	    ehdr->e_phentsize < sizeof(Elf32_Phdr))
		return TEE_ERROR_BAD_FORMAT;

	if (MUL_OVERFLOW(ehdr->e_phentsize, ehdr->e_phnum, &phtab_end) ||
	    ADD_OVERFLOW(phtab_end, ehdr->e_phoff, &phtab_end) ||
	    phtab_end > md_size)
		return TEE_ERROR_BAD_FORMAT;

	phdrs = (const void *)(md + ehdr->e_phoff);
	preamble_len = phdrs[0].p_filesz;

	if (preamble_len >= md_size)
		return TEE_ERROR_BAD_FORMAT;

	*seg = md + preamble_len;
	*seg_size = md_size - preamble_len;
	if (preamble)
		*preamble = preamble_len;

	return TEE_SUCCESS;
}

TEE_Result pas_mbn_take_region(const uint8_t *seg, size_t seg_size,
			       size_t *cursor, size_t len,
			       const uint8_t **ptr, size_t *ptr_len)
{
	if (!len) {
		*ptr = NULL;
		*ptr_len = 0;
		return TEE_SUCCESS;
	}

	if (len > seg_size || *cursor > seg_size - len)
		return TEE_ERROR_BAD_FORMAT;

	*ptr = seg + *cursor;
	*ptr_len = len;
	*cursor += len;

	return TEE_SUCCESS;
}

TEE_Result pas_mbn_parse(const uint8_t *md, size_t md_size,
			 uint32_t hash_size, struct pas_mbn *out)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t oem_cert_size = 0;
	uint32_t oem_meta_size = 0;
	const uint8_t *seg = NULL;
	uint32_t oem_sig_size = 0;
	uint32_t qc_cert_size = 0;
	uint32_t qc_meta_size = 0;
	uint32_t qc_sig_size = 0;
	size_t signed_size = 0;
	uint32_t code_size = 0;
	uint32_t version = 0;
	size_t hdr_size = 0;
	size_t seg_size = 0;
	size_t cursor = 0;

	if (!md || !md_size || !out || !hash_size)
		return TEE_ERROR_BAD_PARAMETERS;

	memset(out, 0, sizeof(*out));

	res = pas_mbn_locate(md, md_size, &seg, &seg_size, NULL);
	if (res)
		return res;

	if (seg_size < MBN_HDR_SIZE_V5)
		return TEE_ERROR_BAD_FORMAT;

	version = pas_mbn_read_u32(seg + MBN_OFF_VERSION);
	switch (version) {
	case PAS_MBN_VERSION_5:
		hdr_size = MBN_HDR_SIZE_V5;
		break;
	case PAS_MBN_VERSION_6:
		hdr_size = MBN_HDR_SIZE_V6;
		break;
	default:
		EMSG("PAS auth: unsupported MBN version %"PRIu32, version);
		return TEE_ERROR_BAD_FORMAT;
	}

	if (seg_size < hdr_size)
		return TEE_ERROR_BAD_FORMAT;

	/*
	 * The MBN header "code_size" field is the hash-table length in bytes,
	 * i.e. num_entries * hash_size (one digest per program header).
	 */
	code_size = pas_mbn_read_u32(seg + MBN_OFF_CODE_SIZE);
	qc_sig_size = pas_mbn_read_u32(seg + MBN_OFF_QC_SIG_SIZE);
	qc_cert_size = pas_mbn_read_u32(seg + MBN_OFF_QC_CERT_SIZE);
	oem_sig_size = pas_mbn_read_u32(seg + MBN_OFF_OEM_SIG_SIZE);
	oem_cert_size = pas_mbn_read_u32(seg + MBN_OFF_OEM_CERT_SIZE);
	if (version == PAS_MBN_VERSION_6) {
		qc_meta_size = pas_mbn_read_u32(seg + MBN_OFF_QC_META_SIZE);
		oem_meta_size = pas_mbn_read_u32(seg + MBN_OFF_OEM_META_SIZE);
	}

	if (!code_size || code_size % hash_size)
		return TEE_ERROR_BAD_FORMAT;

	/*
	 * Payload after the header:
	 *   [qc_meta][oem_meta][hash table][qc_sig][qc_cert][oem_sig][oem_cert]
	 * The signature covers the MBN header followed by
	 * [qc_meta || oem_meta || hash table], so the signed region spans the
	 * header and that payload from the segment start.
	 */
	cursor = hdr_size;
	out->signed_region = seg;

	if (ADD_OVERFLOW(qc_meta_size, oem_meta_size, &signed_size) ||
	    ADD_OVERFLOW(signed_size, code_size, &signed_size) ||
	    ADD_OVERFLOW(signed_size, hdr_size, &signed_size))
		return TEE_ERROR_BAD_FORMAT;

	if (signed_size > seg_size)
		return TEE_ERROR_BAD_FORMAT;
	out->signed_region_size = signed_size;

	res = pas_mbn_take_region(seg, seg_size, &cursor, qc_meta_size,
				  &out->qti_meta, &out->qti_meta_size);
	if (res)
		return res;
	res = pas_mbn_take_region(seg, seg_size, &cursor, oem_meta_size,
				  &out->oem_meta, &out->oem_meta_size);
	if (res)
		return res;

	out->hash_table = seg + cursor;
	out->hash_table_size = code_size;
	out->hash_size = hash_size;
	out->num_entries = code_size / hash_size;
	cursor += code_size;

	res = pas_mbn_take_region(seg, seg_size, &cursor, qc_sig_size,
				  &out->qti_sig, &out->qti_sig_size);
	if (res)
		return res;
	res = pas_mbn_take_region(seg, seg_size, &cursor, qc_cert_size,
				  &out->qti_certs, &out->qti_certs_size);
	if (res)
		return res;
	res = pas_mbn_take_region(seg, seg_size, &cursor, oem_sig_size,
				  &out->oem_sig, &out->oem_sig_size);
	if (res)
		return res;
	res = pas_mbn_take_region(seg, seg_size, &cursor, oem_cert_size,
				  &out->oem_certs, &out->oem_certs_size);
	if (res)
		return res;

	out->version = version;

	/*
	 * Any bytes past the last cert region are a UIE image-encryption
	 * parameter block when they open with the UIE magic. Detecting it lets
	 * the caller reject encrypted images (decryption is not supported).
	 */
	if (cursor + sizeof(uint32_t) <= seg_size &&
	    pas_mbn_read_u32(seg + cursor) == UIE_ENC_PARAM_MAGIC)
		out->uie_encrypted = true;

	return TEE_SUCCESS;
}
