/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2019 Broadcom.
 */

#ifndef BNXT_H
#define BNXT_H

#include <compiler.h>
#include <io.h>
#include <mm/core_memprot.h>
#include <util.h>

#define BNXT_SUCCESS       0
#define BNXT_FAILURE       (!BNXT_SUCCESS)

uint32_t bnxt_write32_multiple(uintptr_t dst,
			       uintptr_t src,
			       uint32_t num_entries,
			       int src_4byte_increment);
void bnxt_chimp_halt(void);
void bnxt_kong_halt(void);
int bnxt_fastboot(uintptr_t addr);
int bnxt_wait_handshake(void);
TEE_Result bnxt_load_fw(int chip_type);

struct bnxt_images_info {
	vaddr_t bnxt_fw_vaddr;
	uint32_t bnxt_fw_len;
	vaddr_t bnxt_cfg_vaddr;
	uint32_t bnxt_cfg_len;
	vaddr_t bnxt_bspd_cfg_vaddr;
	uint32_t bnxt_bspd_cfg_len;
};

int get_bnxt_images_info(struct bnxt_images_info *bnxt_info, int chip_type);

#endif
