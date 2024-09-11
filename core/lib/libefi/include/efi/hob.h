/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2024, Arm Limited and Contributors. All rights reserved.
 *
 * @par Reference(s):
 * - UEFI Platform Initialization Specification
 *   (https://uefi.org/specs/PI/1.8/index.html)
 */

#ifndef __HOB_H
#define __HOB_H

#include <efi/efi_types.h>
#include <efi/hob_guid.h>
#include <efi/mmram.h>
#include <efi/mpinfo.h>

#include <tee_api_types.h>
#include <types_ext.h>

#define HOB_ALIGN 8

/*****************************************************************************
 *                            Hob Generic Header                             *
 *****************************************************************************/

/**
 * HobType values of EFI_HOB_GENERIC_HEADER.
 */
#define EFI_HOB_TYPE_HANDOFF              0x0001
#define EFI_HOB_TYPE_MEMORY_ALLOCATION    0x0002
#define EFI_HOB_TYPE_RESOURCE_DESCRIPTOR  0x0003
#define EFI_HOB_TYPE_GUID_EXTENSION       0x0004
#define EFI_HOB_TYPE_FV                   0x0005
#define EFI_HOB_TYPE_CPU                  0x0006
#define EFI_HOB_TYPE_MEMORY_POOL          0x0007
#define EFI_HOB_TYPE_FV2                  0x0009
#define EFI_HOB_TYPE_LOAD_PEIM_UNUSED     0x000A
#define EFI_HOB_TYPE_UEFI_CAPSULE         0x000B
#define EFI_HOB_TYPE_FV3                  0x000C
#define EFI_HOB_TYPE_UNUSED               0xFFFE
#define EFI_HOB_TYPE_END_OF_HOB_LIST      0xFFFF

struct efi_hob_generic_header {
	uint16_t hob_type;
	uint16_t hob_length;
	uint32_t reserved;
};

/*****************************************************************************
 *                               PHIT Hob.                                   *
 *****************************************************************************/

#define EFI_HOB_HANDOFF_TABLE_VERSION     0x000a

struct efi_hob_handoff_info_table {
	struct efi_hob_generic_header header;
	uint32_t version;
	efi_boot_mode_t  boot_mode;
	efi_physical_address_t efi_memory_top;
	efi_physical_address_t efi_memory_bottom;
	efi_physical_address_t efi_free_memory_top;
	efi_physical_address_t efi_free_memory_bottom;
	efi_physical_address_t efi_end_of_hob_list;
};

/*****************************************************************************
 *                       Resource Descriptor Hob.                            *
 *****************************************************************************/

struct efi_hob_resource_descriptor {
	struct efi_hob_generic_header header;
	TEE_UUID owner;
	efi_resource_type_t resource_type;
	efi_resource_attribute_type_t resource_attribute;
	efi_physical_address_t physical_start;
	uint64_t resource_length;
};

/*****************************************************************************
 *                           Guid Extension Hob.                             *
 *****************************************************************************/
struct efi_hob_guid_type {
	struct efi_hob_generic_header header;
	TEE_UUID name;
	/**
	 * Guid specific data goes here.
	 */
};

/*****************************************************************************
 *                           Firmware Volume Hob.                            *
 *****************************************************************************/
struct efi_hob_firmware_volume {
	struct efi_hob_generic_header header;
	efi_physical_address_t base_address;
	uint64_t length;
	/**
	 * Guid specific data goes here.
	 */
};

/*****************************************************************************
 *                              Interfaces.                                  *
 *****************************************************************************/
struct efi_hob_handoff_info_table *
efi_create_hob_list(vaddr_t mem_begin, size_t mem_len,
		    vaddr_t mem_free_begin, size_t mem_free_len);

TEE_Result
efi_create_resource_desc_hob(struct efi_hob_handoff_info_table *hob_table,
			     efi_resource_type_t resource_type,
			     efi_resource_attribute_type_t resource_attribute,
			     efi_physical_address_t phy_addr_start,
			     uint64_t resource_length);

TEE_Result efi_create_guid_hob(struct efi_hob_handoff_info_table *hob_table,
			       TEE_UUID *guid, uint16_t data_length,
			       void **data);

TEE_Result efi_create_fv_hob(struct efi_hob_handoff_info_table *hob_table,
			     efi_physical_address_t base_addr, uint64_t size);

#endif /*__HOB_H */
