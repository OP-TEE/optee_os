/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __FUSEPROV_V3_H
#define __FUSEPROV_V3_H

#include <stddef.h>
#include <tee_api_types.h>
#include <types_ext.h>

/*
 * Authenticate a sec.elf with TME-Lite, then program its fuse list, held in
 * non-secure memory at @secdat_pa. Fuses written before a failure stay.
 */
TEE_Result fuseprov_v3_blow_secelf(const void *elf, size_t elf_len,
				   paddr_t secdat_pa, size_t secdat_len);

#endif /* __FUSEPROV_V3_H */
