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
#define BNXT_NS3_CFG_IMAGE_SIG		0xCF54321A

#define BNXT_BSPD_CFG_LEN	512

#define QSPI_BASE		QSPI_MEM_BASE
#define QSPI_BNXT_IMG		(QSPI_BASE + 0x400000)
#define QSPI_BSPD_ADDR		(QSPI_BASE + 0x700000)

#define BCM_NS3		1

static void set_bnxt_images_info(struct bnxt_images_info *bnxt_info,
				 int chip_type, vaddr_t src, vaddr_t dst);

static struct bnxt_img_header {
	uint32_t bnxt_fw_ns3_sig;
	uint32_t bnxt_fw_ns3_size;
	uint32_t bnxt_ns3_cfg_sig;
	uint32_t bnxt_ns3_cfg_size;
} *img_header;

static int verify_header(vaddr_t mem)
{
	img_header = (struct bnxt_img_header *)mem;

	if (img_header->bnxt_fw_ns3_sig == BNXT_FW_NS3_IMAGE_SIG &&
	    img_header->bnxt_ns3_cfg_sig == BNXT_NS3_CFG_IMAGE_SIG)
		return BNXT_SUCCESS;
	return BNXT_FAILURE;
}

static void set_bnxt_images_info(struct bnxt_images_info *bnxt_info,
				 int chip_type, vaddr_t src, vaddr_t dst)
{
	uint32_t len = 0;
	struct bnxt_img_header *dst_header = NULL;
	uint32_t fw_image_offset = sizeof(struct bnxt_img_header);

	img_header = (struct bnxt_img_header *)src;
	if (dst) {
		dst_header = (struct bnxt_img_header *)dst;
		memcpy(dst_header, img_header, sizeof(*img_header));
		dst += sizeof(*img_header);

		if (chip_type != BCM_NS3) {
			dst_header->bnxt_fw_ns3_size = 0;
			dst_header->bnxt_ns3_cfg_size = 0;
		}
	}

	if (chip_type == BCM_NS3) {
		len = img_header->bnxt_fw_ns3_size;
		bnxt_info->bnxt_fw_vaddr = src + fw_image_offset;
		bnxt_info->bnxt_fw_len = len;
		if (dst) {
			memcpy((void *)dst, (void *)(src + fw_image_offset),
			       len);
			dst += len;
		}

		fw_image_offset += len;

		len = img_header->bnxt_ns3_cfg_size;
		bnxt_info->bnxt_cfg_vaddr = src + fw_image_offset;
		bnxt_info->bnxt_cfg_len = len;
		if (dst) {
			memcpy((void *)dst, (void *)(src + fw_image_offset),
			       len);
		}
	}
}

int get_bnxt_images_info(struct bnxt_images_info *bnxt_info, int chip_type,
			 vaddr_t ddr_dest)
{
	vaddr_t flash_dev_vaddr = 0;

	bnxt_info->bnxt_bspd_cfg_len = BNXT_BSPD_CFG_LEN;

	/* First verify if images are on sec mem */
	if (verify_header(ddr_dest + BNXT_IMG_SECMEM_OFFSET) == BNXT_SUCCESS) {
		DMSG("Images found on sec memory");

		bnxt_info->bnxt_bspd_cfg_vaddr = ddr_dest;

		set_bnxt_images_info(bnxt_info, chip_type,
				     ddr_dest + BNXT_IMG_SECMEM_OFFSET, 0);
	} else {
		flash_dev_vaddr = (vaddr_t)
			phys_to_virt(QSPI_BNXT_IMG, MEM_AREA_IO_NSEC,
				     sizeof(struct bnxt_img_header));

		if (verify_header(flash_dev_vaddr) != BNXT_SUCCESS) {
			EMSG("failed to load fw images");
			return BNXT_FAILURE;
		}

		DMSG("Images loading from flash memory");
		bnxt_info->bnxt_bspd_cfg_vaddr =
				(vaddr_t)phys_to_virt(QSPI_BSPD_ADDR,
						      MEM_AREA_IO_NSEC,
						      BNXT_BSPD_CFG_LEN);
		memcpy((void *)ddr_dest, (void *)bnxt_info->bnxt_bspd_cfg_vaddr,
		       BNXT_BSPD_CFG_LEN);

		set_bnxt_images_info(bnxt_info, chip_type, flash_dev_vaddr,
				     ddr_dest + BNXT_IMG_SECMEM_OFFSET);
	}

	return BNXT_SUCCESS;
}
