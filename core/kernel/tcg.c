// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2022, Linaro Limited
 */

#include <compiler.h>
#include <drivers/tpm2_chip.h>
#include <initcall.h>
#include <io.h>
#include <kernel/tcg.h>
#include <kernel/tpm.h>
#include <malloc.h>
#include <string.h>
#include <tpm2.h>
#include <trace.h>

static struct tcg_pcr_ops *pcr_provider;

static TEE_Result tcg_get_pcr_info(uint32_t *selection_mask,
				   uint32_t *active_mask, uint32_t *num_pcr)
{
	if (!pcr_provider || !pcr_provider->pcr_info)
		return TEE_ERROR_GENERIC;

	return pcr_provider->pcr_info(selection_mask, active_mask, num_pcr);
}

static TEE_Result tcg_pcr_extend(uint32_t pcr_index,
				 struct tpml_digest_values *digest_list)
{
	uint32_t i = 0;

	if (!pcr_provider || !pcr_provider->pcr_extend)
		return TEE_ERROR_GENERIC;

	for (i = 0; i < digest_list->count; i++) {
		uint32_t alg = digest_list->digests[i].hash_alg;
		uint8_t *digest = (uint8_t *)&digest_list->digests[i].digest;

		if (pcr_provider->pcr_extend(pcr_index, alg, digest,
					     tpm2_get_alg_len(alg))) {
			EMSG("Failed to extend PCR");
			return TEE_ERROR_COMMUNICATION;
		}
	}

	return TEE_SUCCESS;
}

static uint32_t tcg_event_final_size(struct tpml_digest_values *digest_list)
{
	uint32_t len = 0;
	size_t i = 0;

	len = offsetof(struct tcg_pcr_event2, digests);
	len += offsetof(struct tpml_digest_values, digests);
	for (i = 0; i < digest_list->count; i++) {
		uint16_t hash_alg = digest_list->digests[i].hash_alg;

		len += offsetof(struct tpmt_ha, digest);
		len += tpm2_get_alg_len(hash_alg);
	}
	len += sizeof(uint32_t); /* tcg_pcr_event2 event_size*/

	return len;
}

/*
 * tcg_parse_event_log_header() -  Parse and verify the event log header fields
 *
 * @buffer:			Pointer to the start of the eventlog
 * @size:			Size of the eventlog
 * @pos:			Return offset of the next event in buffer right
 *				after the event header i.e specID
 *
 * Return:	status code
 */
static TEE_Result tcg_parse_event_log_header(void *buffer, uint32_t size,
					     uint32_t *pos)
{
	struct tcg_pcr_event *event_header = (struct tcg_pcr_event *)buffer;
	uint32_t i = 0;

	if (size < sizeof(*event_header))
		return TEE_ERROR_BAD_FORMAT;

	if (get_unaligned_le32(&event_header->pcr_index) != 0 ||
	    get_unaligned_le32(&event_header->event_type) != EV_NO_ACTION)
		return TEE_ERROR_BAD_FORMAT;

	for (i = 0; i < sizeof(event_header->digest); i++) {
		if (event_header->digest[i])
			return TEE_ERROR_BAD_FORMAT;
	}

	*pos += sizeof(*event_header);

	return TEE_SUCCESS;
}

/*
 * tcg_parse_specid_event() -  Parse and verify the specID Event in the eventlog
 *
 * @buffer:		Pointer to the start of the eventlog
 * @log_size:		Size of the eventlog
 * @pos:		[in] Offset of specID event in the eventlog buffer
 *			[out] Return offset of the next event in the buffer
 *			after the specID
 * @digest_list:	list of digests in the event
 *
 * Return:		status code
 */
static TEE_Result tcg_parse_specid_event(void *buffer, uint32_t log_size,
					 uint32_t *pos,
					 struct tpml_digest_values *digest_list)
{
	struct tcg_efi_spec_id_event *spec_event = NULL;
	struct tcg_pcr_event *event_header = buffer;
	uint8_t vendor_sz = 0;
	uint16_t hash_alg = 0;
	uint32_t active = 0;
	uint32_t alg_count = 0;
	uint32_t i = 0;
	uint32_t pcr_count = 0;
	uint32_t spec_active = 0;
	uint32_t supported = 0;
	size_t spec_event_size = 0;

	if ((*pos + sizeof(*spec_event)) > log_size)
		return TEE_ERROR_BAD_FORMAT;

	/* Check specID event data */
	spec_event = (struct tcg_efi_spec_id_event *)((uintptr_t)buffer + *pos);
	/* Check for signature */
	if (memcmp(spec_event->signature, TCG_EFI_SPEC_ID_EVENT_SIGNATURE_03,
		   sizeof(TCG_EFI_SPEC_ID_EVENT_SIGNATURE_03))) {
		EMSG("specID Event: Signature mismatch");
		return TEE_ERROR_BAD_FORMAT;
	}

	if (spec_event->spec_version_minor !=
			TCG_EFI_SPEC_ID_EVENT_SPEC_VERSION_MINOR_TPM2 ||
	    spec_event->spec_version_major !=
			TCG_EFI_SPEC_ID_EVENT_SPEC_VERSION_MAJOR_TPM2)
		return TEE_ERROR_BAD_FORMAT;

	if (!spec_event->number_of_algorithms) {
		EMSG("specID Event: Number of algorithms incorrect");
		return TEE_ERROR_BAD_FORMAT;
	}

	alg_count = spec_event->number_of_algorithms;

	if (alg_count > TPM2_NUM_PCR_BANKS)
		return TEE_ERROR_BAD_FORMAT;

	if (tcg_get_pcr_info(&supported, &active, &pcr_count))
		return TEE_ERROR_COMMUNICATION;

	digest_list->count = 0;
	/*
	 * We have to take care that the sequence of algorithms that we record
	 * in digest_list matches the sequence in eventlog.
	 */
	for (i = 0; i < alg_count; i++) {
		hash_alg =
		  get_unaligned_le16(&spec_event->digest_sizes[i].algorithm_id);

		if (!(supported & tpm2_alg_to_tcg_mask(hash_alg))) {
			EMSG("specID Event: Unsupported algorithm");
			return TEE_ERROR_BAD_FORMAT;
		}
		digest_list->digests[digest_list->count++].hash_alg = hash_alg;

		spec_active |= tpm2_alg_to_tcg_mask(hash_alg);
	}

	/*
	 * TCG specification expects the event log to have hashes for all
	 * active PCR's
	 */
	if (spec_active != active) {
		/*
		 * Previous stage bootloader should know all the active PCR's
		 * and use them in the Eventlog.
		 */
		EMSG("specID Event: All active hash alg not present");
		return TEE_ERROR_BAD_FORMAT;
	}

	/*
	 * the size of the spec event and placement of vendor_info_size
	 * depends on supported algorithms
	 */
	spec_event_size =
		offsetof(struct tcg_efi_spec_id_event, digest_sizes) +
		alg_count * sizeof(spec_event->digest_sizes[0]);

	if (*pos + spec_event_size >= log_size)
		return TEE_ERROR_BAD_FORMAT;

	vendor_sz = *(uint8_t *)((uintptr_t)buffer + *pos + spec_event_size);

	spec_event_size += sizeof(vendor_sz) + vendor_sz;
	*pos += spec_event_size;

	if (get_unaligned_le32(&event_header->event_size) != spec_event_size) {
		EMSG("specID event: header event size mismatch");
		/* Right way to handle this can be to call SetActive PCR's */
		return TEE_ERROR_BAD_FORMAT;
	}

	return TEE_SUCCESS;
}

/*
 * tcg_parse_event() -  Parse the event in the eventlog
 *
 * @buffer:		Pointer to the start of the eventlog
 * @log_size:		Size of the eventlog
 * @offset:		[in] Offset of the event in the eventlog buffer
 *			[out] Return offset of the next event in the buffer
 * @digest_list:	list of digests in the event.
 * @pcr			Index of the PCR in the event
 *
 * Return:		status code
 */
static TEE_Result tcg_parse_event(void *buffer, uint32_t log_size,
				  uint32_t *offset,
				  struct tpml_digest_values *digest_list,
				  uint32_t *pcr)
{
	struct tcg_pcr_event2 *event = NULL;
	uint32_t count = 0, size = 0, event_size = 0;
	uint32_t i = 0;
	size_t pos = 0;

	event_size = tcg_event_final_size(digest_list);
	if (*offset >= log_size || *offset + event_size > log_size) {
		EMSG("Event exceeds log size");
		return TEE_ERROR_BAD_FORMAT;
	}

	event = (struct tcg_pcr_event2 *)((uintptr_t)buffer + *offset);
	*pcr = get_unaligned_le32(&event->pcr_index);

	/* get the count */
	count = get_unaligned_le32(&event->digests.count);
	if (count != digest_list->count)
		return TEE_ERROR_BAD_FORMAT;

	/*
	 * Element 'digests' of type tpml_digest_values in struct tcg_pcr_event2
	 * is a list of digests. The count of digests in this list depends on
	 * the number of active PCR banks. Further this list contains elements
	 * of type tpmt_ha whose size depends on the hash algorithm. So, the
	 * position of each of the element in the list (of type tpmt_ha) needs
	 * to be calculated.
	 */
	pos = offsetof(struct tcg_pcr_event2, digests);

	/* Position of first element of type tpmt_ha in the digest list */
	pos += offsetof(struct tpml_digest_values, digests);

	for (i = 0; i < digest_list->count; i++) {
		uint16_t alg = 0;
		uint16_t hash_alg = digest_list->digests[i].hash_alg;
		uint8_t *digest = (uint8_t *)&digest_list->digests[i].digest;

		/* Element hash_alg in struct tpmt_ha */
		alg = get_unaligned_le16((void *)((uintptr_t)event + pos));

		/*
		 * The sequence of algorithm must match that from digest list
		 * in spec ID event.
		 */
		if (alg != hash_alg)
			return TEE_ERROR_BAD_FORMAT;

		pos += offsetof(struct tpmt_ha, digest);
		memcpy(digest, (void *)((uintptr_t)event + pos),
		       tpm2_get_alg_len(hash_alg));

		/* Calculate position of next tpmt_ha element in the event */
		pos += tpm2_get_alg_len(hash_alg);
	}

	/* WARNING - Since size of digest lists can vary, the
	 * position of event and event_size elements in tcg_pcr_event2 needs to
	 * be determined dynamically.
	 */
	size = get_unaligned_le32((void *)((uintptr_t)event + pos));
	event_size += size;
	pos += sizeof(uint32_t); /* tcg_pcr_event2 event_size*/
	pos += size;

	/* make sure the calculated buffer is what we checked against */
	if (pos != event_size)
		return TEE_ERROR_BAD_FORMAT;

	if (pos > log_size)
		return TEE_ERROR_BAD_FORMAT;

	*offset += pos;

	return TEE_SUCCESS;
}

/**
 * tcg_process_fw_eventlog() - Parse the eventlog and extend the PCR's
 *
 * Return:	status code
 */
TEE_Result tcg_process_fw_eventlog(void)
{
	void *buffer = NULL;
	void *tmp = NULL;
	uint32_t i = 0, pcr = 0, pos = 0;
	size_t digest_list_sz = 0;
	size_t sz = TPM2_EVENT_LOG_SIZE;
	TEE_Result ret = TEE_SUCCESS;
	struct tpml_digest_values *digest_list = NULL;

	if (!pcr_provider) {
		EMSG("No provider available for PCR's");
		return TEE_ERROR_GENERIC;
	}

	buffer = malloc(TPM2_EVENT_LOG_SIZE);
	if (!buffer) {
		EMSG("Error allocating mem");
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	ret = tpm_get_event_log(buffer, &sz);
	if (ret == TEE_ERROR_SHORT_BUFFER) {
		tmp = realloc(buffer, sz);
		if (!tmp)
			goto out;

		buffer = tmp;
		/* Try to get the eventlog again */
		ret = tpm_get_event_log(buffer, &sz);
	}

	if (ret)
		goto out;

	pos = 0;
	/* Parse the eventlog to check for its validity */
	ret = tcg_parse_event_log_header(buffer, sz, &pos);
	if (ret) {
		EMSG("Error parsing event log header");
		goto out;
	}

	digest_list_sz = sizeof(struct tpml_digest_values);
	digest_list = malloc(digest_list_sz);
	if (!digest_list) {
		EMSG("Error allocating mem");
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	/* Populate the digest_list with digest algs by parsing specid event */
	ret = tcg_parse_specid_event(buffer, sz, &pos, digest_list);
	if (ret) {
		EMSG("Error parsing SPEC ID Event");
		goto out;
	}

	while (pos < sz) {
		ret = tcg_parse_event(buffer, sz, &pos, digest_list,
				      &pcr);
		if (ret) {
			EMSG("Error parsing event");
			goto out;
		}

		ret = tcg_pcr_extend(pcr, digest_list);
		if (ret != TEE_SUCCESS) {
			EMSG("Error in extending PCR");
			goto out;
		}

		/* Clear the digest for next event */
		for (i = 0; i < digest_list->count; i++) {
			uint16_t hash_alg = digest_list->digests[i].hash_alg;
			uint8_t *digest =
			   (uint8_t *)&digest_list->digests[i].digest;

			/* Clear the digest in the digest_list */
			memset(digest, 0, tpm2_get_alg_len(hash_alg));
		}
	}

out:
	free(digest_list);
	free(buffer);

	return ret;
}

boot_final(tcg_process_fw_eventlog);

TEE_Result register_tcg_pcr_provider(struct tcg_pcr_ops *ops)
{
	/* Only 1 PCR provider is supported */
	if (pcr_provider) {
		EMSG("Provider already registered");
		return TEE_ERROR_GENERIC;
	}

	if (!ops)
		return TEE_ERROR_GENERIC;

	pcr_provider = ops;

	return TEE_SUCCESS;
}
