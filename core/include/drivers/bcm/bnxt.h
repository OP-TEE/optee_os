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
void bnxt_handshake_clear(void);
void bnxt_chimp_halt(void);
void bnxt_kong_halt(void);
int bnxt_fastboot(uintptr_t addr);
uint32_t bnxt_wait_handshake(uint32_t timeout);
uint32_t bnxt_health_status(void);
TEE_Result bnxt_load_fw(int chip_type);
TEE_Result bnxt_copy_crash_dump(uint8_t *d, uint32_t offset, uint32_t len);

struct bnxt_images_info {
	vaddr_t bnxt_fw_vaddr;
	uint32_t bnxt_fw_len;
	vaddr_t bnxt_cfg_vaddr;
	uint32_t bnxt_cfg_len;
	vaddr_t bnxt_bspd_cfg_vaddr;
	uint32_t bnxt_bspd_cfg_len;
};

/* Reserve 1K for BSPD data */
#define BNXT_IMG_SECMEM_OFFSET	0x400

int get_bnxt_images_info(struct bnxt_images_info *bnxt_info,
			 int chip_type, vaddr_t ddr_dest);

#endif
