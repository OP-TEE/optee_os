// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2019 Broadcom.
 */

#include <drivers/bcm/bnxt.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <util.h>

#define BNXT_FW_NS3_IMAGE_SIG		0xFF12345A
#define BNXT_FW_NS3Z_IMAGE_SIG		0xFF12345B
#define BNXT_NS3_CFG_IMAGE_SIG		0xCF54321A
#define BNXT_NS3Z_CFG_IMAGE_SIG		0xCF54321B

#define BNXT_BSPD_CFG_LEN	512

#define QSPI_BASE		QSPI_MEM_BASE
#define QSPI_BNXT_IMG		(QSPI_BASE + 0x400000)
#define QSPI_BSPD_ADDR		(QSPI_BASE + 0x700000)

#define BCM_NS3		1
#define BCM_NS3Z	2

static struct bnxt_img_header {
	uint32_t bnxt_fw_ns3_sig;
	uint32_t bnxt_fw_ns3_size;
	uint32_t bnxt_fw_ns3z_sig;
	uint32_t bnxt_fw_ns3z_size;
	uint32_t bnxt_ns3_cfg_sig;
	uint32_t bnxt_ns3_cfg_size;
	uint32_t bnxt_ns3z_cfg_sig;
	uint32_t bnxt_ns3z_cfg_size;
} *img_header;

int get_bnxt_images_info(struct bnxt_images_info *bnxt_info, int chip_type)
{
	uint32_t len = 0;
	uint32_t fw_image_offset = sizeof(struct bnxt_img_header);
	vaddr_t flash_dev_vaddr =
			(uintptr_t)((vaddr_t)phys_to_virt(QSPI_BNXT_IMG,
							  MEM_AREA_IO_NSEC));

	bnxt_info->bnxt_bspd_cfg_vaddr =
			(uintptr_t)((vaddr_t)phys_to_virt(QSPI_BSPD_ADDR,
							  MEM_AREA_IO_NSEC));

	bnxt_info->bnxt_bspd_cfg_len = BNXT_BSPD_CFG_LEN;

	img_header = (struct bnxt_img_header *)flash_dev_vaddr;

	if (img_header->bnxt_fw_ns3_sig != BNXT_FW_NS3_IMAGE_SIG) {
		EMSG("Invalid Nitro bin");
		return BNXT_FAILURE;
	}

	len = img_header->bnxt_fw_ns3_size;

	if (chip_type == BCM_NS3) {
		bnxt_info->bnxt_fw_vaddr = flash_dev_vaddr + fw_image_offset;
		bnxt_info->bnxt_fw_len = len;
	}

	fw_image_offset += len;

	if (img_header->bnxt_fw_ns3z_sig != BNXT_FW_NS3Z_IMAGE_SIG) {
		EMSG("Invalid Nitro bin");
		return BNXT_FAILURE;
	}

	len = img_header->bnxt_fw_ns3z_size;

	if (chip_type == BCM_NS3Z) {
		bnxt_info->bnxt_fw_vaddr = flash_dev_vaddr + fw_image_offset;
		bnxt_info->bnxt_fw_len = len;
	}

	fw_image_offset += len;

	if (img_header->bnxt_ns3_cfg_sig != BNXT_NS3_CFG_IMAGE_SIG) {
		EMSG("Invalid Nitro config");
		return BNXT_FAILURE;
	}

	len = img_header->bnxt_ns3_cfg_size;

	if (chip_type == BCM_NS3) {
		bnxt_info->bnxt_cfg_vaddr = flash_dev_vaddr + fw_image_offset;
		bnxt_info->bnxt_cfg_len = len;
	}

	fw_image_offset += len;

	if (img_header->bnxt_ns3z_cfg_sig != BNXT_NS3Z_CFG_IMAGE_SIG) {
		EMSG("Invalid Nitro config");
		return BNXT_FAILURE;
	}

	len = img_header->bnxt_ns3z_cfg_size;

	if (chip_type == BCM_NS3Z) {
		bnxt_info->bnxt_cfg_vaddr = flash_dev_vaddr + fw_image_offset;
		bnxt_info->bnxt_cfg_len = len;
	}

	return BNXT_SUCCESS;
}
