// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <pas_utils.h>
#include <string.h>

TEE_Result pas_utils_save_metadata(struct qcom_pas_session *s, uint32_t pas_id,
				   void *meta_data, size_t size)
{
	struct pas_md_slot *slot = NULL;
	void *meta_data_copy = NULL;
	size_t i = 0;

	if (!size)
		return TEE_ERROR_BAD_PARAMETERS;

	if (size && !meta_data)
		return TEE_ERROR_BAD_PARAMETERS;

	slot = get_meta_data_slot(s, pas_id);
	if (!slot) {
		for (i = 0; i < PAS_MD_SLOTS; i++) {
			if (!s->slots[i].in_use) {
				slot = &s->slots[i];
				goto found;
			}
		}
		EMSG("PAS auth: no free md slot (pas_id=%#"PRIx32")", pas_id);
		return TEE_ERROR_OUT_OF_MEMORY;
	}

found:
	meta_data_copy = TEE_Malloc(size, TEE_MALLOC_FILL_ZERO);
	if (!meta_data_copy)
		return TEE_ERROR_OUT_OF_MEMORY;
	memcpy(meta_data_copy, meta_data, size);

	TEE_Free(slot->meta_data);
	slot->meta_data = meta_data_copy;
	slot->meta_data_size = size;
	slot->pas_id = pas_id;
	slot->in_use = true;
	slot->ready = false;
	memset(&slot->mbn, 0, sizeof(slot->mbn));

	return TEE_SUCCESS;
}

TEE_Result pas_utils_release_metadata(struct qcom_pas_session *s,
				      uint32_t pas_id)
{
	struct pas_md_slot *slot = get_meta_data_slot(s, pas_id);

	if (!slot)
		return TEE_SUCCESS;

	TEE_Free(slot->meta_data);
	slot->meta_data = NULL;
	slot->meta_data_size = 0;
	slot->ready = false;
	slot->in_use = false;
	memset(&slot->mbn, 0, sizeof(slot->mbn));

	return TEE_SUCCESS;
}
