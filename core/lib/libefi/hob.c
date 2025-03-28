// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2024, Arm Limited and Contributors. All rights reserved.
 *
 * @par Reference(s):
 * - UEFI Platform Initialization Specification
 *   (https://uefi.org/specs/PI/1.8/index.html)
 */

#include <assert.h>
#include <inttypes.h>
#include <string.h>
#include <tee_api_defines.h>
#include <trace.h>
#include <util.h>

#include <efi/hob.h>

static void *create_hob(struct efi_hob_handoff_info_table *hob_table,
			uint16_t hob_type, uint16_t hob_length)
{
	size_t free_mem_size = 0;
	struct efi_hob_generic_header *new_hob = NULL;
	struct efi_hob_generic_header *hob_end = NULL;

	hob_length = ROUNDUP(hob_length, HOB_ALIGN);

	assert(hob_table && hob_length);

	free_mem_size = hob_table->efi_free_memory_top -
			hob_table->efi_free_memory_bottom;

	/*
	 * hob_length already including sizeof(efi_hob_generic_header).
	 * See the each export interface create_xxx_hob.
	 */
	if (hob_length > free_mem_size)
		return NULL;

	new_hob = (void *)hob_table->efi_end_of_hob_list;
	new_hob->hob_type = hob_type;
	new_hob->hob_length = hob_length;
	new_hob->reserved = 0;

	hob_end = (void *)((vaddr_t)new_hob + hob_length);
	hob_end->hob_type = EFI_HOB_TYPE_END_OF_HOB_LIST;
	hob_end->hob_length = sizeof(struct efi_hob_generic_header);
	hob_end->reserved = 0;

	hob_table->efi_end_of_hob_list = (vaddr_t)hob_end;
	hob_table->efi_free_memory_bottom = (vaddr_t)(hob_end + 1);

	return new_hob;
}

struct efi_hob_handoff_info_table *
efi_create_hob_list(vaddr_t mem_begin, size_t mem_len,
		    vaddr_t mem_free_begin, size_t mem_free_len)
{
	struct efi_hob_handoff_info_table *hob_table = NULL;
	struct efi_hob_generic_header *hob_end = NULL;

	if (!mem_begin || !mem_free_begin || !mem_len || !mem_free_len)
		return NULL;

	hob_table = (void *)mem_free_begin;
	hob_end = (void *)(hob_table + 1);

	hob_table->header.hob_type = EFI_HOB_TYPE_HANDOFF;
	hob_table->header.hob_length =
		sizeof(struct efi_hob_handoff_info_table);
	hob_table->header.reserved = 0;

	hob_end->hob_type = EFI_HOB_TYPE_END_OF_HOB_LIST;
	hob_end->hob_length = sizeof(struct efi_hob_generic_header);
	hob_end->reserved = 0;

	hob_table->version = EFI_HOB_HANDOFF_TABLE_VERSION;
	hob_table->boot_mode = BOOT_WITH_FULL_CONFIGURATION;

	hob_table->efi_memory_top = (vaddr_t)(mem_begin + mem_len);
	hob_table->efi_memory_bottom = (vaddr_t)mem_begin;
	hob_table->efi_free_memory_top = (vaddr_t)mem_begin + mem_free_len;
	hob_table->efi_free_memory_bottom = (vaddr_t)(hob_end + 1);
	hob_table->efi_end_of_hob_list = (vaddr_t)hob_end;

	return hob_table;
}

TEE_Result
efi_create_resource_desc_hob(struct efi_hob_handoff_info_table *hob_table,
			     efi_resource_type_t resource_type,
			     efi_resource_attribute_type_t resource_attribute,
			     efi_physical_address_t phy_addr_start,
			     uint64_t resource_length)
{
	struct efi_hob_resource_descriptor *rd_hop = NULL;

	rd_hop = create_hob(hob_table, EFI_HOB_TYPE_RESOURCE_DESCRIPTOR,
			    sizeof(struct efi_hob_resource_descriptor));

	if (!rd_hop)
		return TEE_ERROR_OUT_OF_MEMORY;

	rd_hop->resource_type = resource_type;
	rd_hop->resource_attribute = resource_attribute;
	rd_hop->physical_start = phy_addr_start;
	rd_hop->resource_length = resource_length;
	memset(&rd_hop->owner, 0, sizeof(TEE_UUID));

	return TEE_SUCCESS;
}

TEE_Result efi_create_guid_hob(struct efi_hob_handoff_info_table *hob_table,
			       TEE_UUID *guid, uint16_t data_length,
			       void **data)
{
	struct efi_hob_guid_type *guid_hob = NULL;
	uint16_t hob_length = 0;

	hob_length = data_length + sizeof(struct efi_hob_guid_type);

	if (!guid || !data || hob_length < data_length)
		return TEE_ERROR_BAD_PARAMETERS;

	guid_hob = create_hob(hob_table,
			      EFI_HOB_TYPE_GUID_EXTENSION, hob_length);
	if (!guid_hob) {
		*data = NULL;

		return TEE_ERROR_OUT_OF_MEMORY;
	}

	memcpy(&guid_hob->name, guid, sizeof(TEE_UUID));

	*data = (void *)(guid_hob + 1);

	return TEE_SUCCESS;
}

TEE_Result efi_create_fv_hob(struct efi_hob_handoff_info_table *hob_table,
			     efi_physical_address_t base_addr, uint64_t size)
{
	struct efi_hob_firmware_volume *fv_hob = NULL;

	fv_hob = create_hob(hob_table, EFI_HOB_TYPE_FV,
			    sizeof(struct efi_hob_firmware_volume));
	if (!fv_hob)
		return TEE_ERROR_OUT_OF_MEMORY;

	fv_hob->base_address = base_addr;
	fv_hob->length = size;

	return TEE_SUCCESS;
}
