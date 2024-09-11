/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2024, Arm Limited and Contributors. All rights reserved.
 */

#ifndef __EFI_TYPES_H
#define __EFI_TYPES_H

#include <stdint.h>

typedef uint64_t efi_physical_address_t;

/*****************************************************************************
 *                            EFI_BOOT_MODE                                  *
 *****************************************************************************/

typedef uint32_t efi_boot_mode_t;
/**
 * EFI boot mode.
 */
#define BOOT_WITH_FULL_CONFIGURATION                   0x00
#define BOOT_WITH_MINIMAL_CONFIGURATION                0x01
#define BOOT_ASSUMING_NO_CONFIGURATION_CHANGES         0x02
#define BOOT_WITH_FULL_CONFIGURATION_PLUS_DIAGNOSTICS  0x03
#define BOOT_WITH_DEFAULT_SETTINGS                     0x04
#define BOOT_ON_S4_RESUME                              0x05
#define BOOT_ON_S5_RESUME                              0x06
#define BOOT_WITH_MFG_MODE_SETTINGS                    0x07
#define BOOT_ON_S2_RESUME                              0x10
#define BOOT_ON_S3_RESUME                              0x11
#define BOOT_ON_FLASH_UPDATE                           0x12
#define BOOT_IN_RECOVERY_MODE                          0x20

/*****************************************************************************
 *                            EFI_RESOURCE_TYPE                              *
 *****************************************************************************/

typedef uint32_t efi_resource_type_t;

/**
 * Value of EFI_RESOURCE_TYPE used in EFI_HOB_RESOURCE_DESCRIPTOR.
 */
#define EFI_RESOURCE_SYSTEM_MEMORY          0x00000000
#define EFI_RESOURCE_MEMORY_MAPPED_IO       0x00000001
#define EFI_RESOURCE_IO                     0x00000002
#define EFI_RESOURCE_FIRMWARE_DEVICE        0x00000003
#define EFI_RESOURCE_MEMORY_MAPPED_IO_PORT  0x00000004
#define EFI_RESOURCE_MEMORY_RESERVED        0x00000005
#define EFI_RESOURCE_IO_RESERVED            0x00000006

/*****************************************************************************
 *                       EFI_RESOURCE_ATTRIBUTE_TYPE                         *
 *****************************************************************************/

typedef uint32_t efi_resource_attribute_type_t;

#define EFI_RESOURCE_ATTR_PRESENT                  0x00000001
#define EFI_RESOURCE_ATTR_INITIALIZED              0x00000002
#define EFI_RESOURCE_ATTR_TESTED                   0x00000004
#define EFI_RESOURCE_ATTR_RD_PROTECTED             0x00000080
#define EFI_RESOURCE_ATTR_WR_PROTECTED             0x00000100
#define EFI_RESOURCE_ATTR_EXECUTION_PROTECTED      0x00000200
#define EFI_RESOURCE_ATTR_PERSISTENT               0x00800000
#define EFI_RESOURCE_ATTR_SINGLE_BIT_ECC           0x00000008
#define EFI_RESOURCE_ATTR_MULTIPLE_BIT_ECC         0x00000010
#define EFI_RESOURCE_ATTR_ECC_RESERVED_1           0x00000020
#define EFI_RESOURCE_ATTR_ECC_RESERVED_2           0x00000040
#define EFI_RESOURCE_ATTR_UNCACHEABLE              0x00000400
#define EFI_RESOURCE_ATTR_WR_COMBINEABLE           0x00000800
#define EFI_RESOURCE_ATTR_WR_THROUGH_CACHEABLE     0x00001000
#define EFI_RESOURCE_ATTR_WR_BACK_CACHEABLE        0x00002000
#define EFI_RESOURCE_ATTR_16_BIT_IO                0x00004000
#define EFI_RESOURCE_ATTR_32_BIT_IO                0x00008000
#define EFI_RESOURCE_ATTR_64_BIT_IO                0x00010000
#define EFI_RESOURCE_ATTR_UNCACHED_EXPORTED        0x00020000
#define EFI_RESOURCE_ATTR_RD_PROTECTABLE           0x00100000
#define EFI_RESOURCE_ATTR_WR_PROTECTABLE           0x00200000
#define EFI_RESOURCE_ATTR_EXECUTION_PROTECTABLE    0x00400000
#define EFI_RESOURCE_ATTR_PERSISTABLE              0x01000000
#define EFI_RESOURCE_ATTR_RD_ONLY_PROTECTED        0x00040000
#define EFI_RESOURCE_ATTR_RD_ONLY_PROTECTABLE      0x00080000
#define EFI_RESOURCE_ATTR_MORE_RELIABLE            0x02000000

#endif
