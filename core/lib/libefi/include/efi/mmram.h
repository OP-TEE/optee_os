/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2024, Arm Limited and Contributors. All rights reserved.
 *
 * @par Reference(s):
 * - UEFI Platform Initialization Specification
 *   (https://uefi.org/specs/PI/1.8/index.html)
 */

#ifndef __MMRAM_H
#define __MMRAM_H

#include "efi_types.h"

/**
 * MMRAM states and capabilities
 * Cf) UEFI Platform Initialization Specification Version 1.8, IV-5.3.5
 */
#define EFI_MMRAM_OPEN                0x00000001
#define EFI_MMRAM_CLOSED              0x00000002
#define EFI_MMRAM_LOCKED              0x00000004
#define EFI_CACHEABLE                 0x00000008
#define EFI_ALLOCATED                 0x00000010
#define EFI_NEEDS_TESTING             0x00000020
#define EFI_NEEDS_ECC_INITIALIZATION  0x00000040

#define EFI_SMRAM_OPEN    EFI_MMRAM_OPEN
#define EFI_SMRAM_CLOSED  EFI_MMRAM_CLOSED
#define EFI_SMRAM_LOCKED  EFI_MMRAM_LOCKED

struct efi_mmram_descriptor {
	efi_physical_address_t physical_start;
	efi_physical_address_t cpu_start;
	uint64_t physical_size;
	uint64_t region_state;
};

/**
 * MMRAM block descriptor
 * This definition comes from
 *     https://github.com/samimujawar/edk2/blob/master/StandaloneMmPkg/Include/Guid/MmramMemoryReserve.h
 */
struct efi_mmram_hob_descriptor_block {
	uint32_t number_of_mm_reserved_regions;
	struct efi_mmram_descriptor descriptor[];
};

#endif
