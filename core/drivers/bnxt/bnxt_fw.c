// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2019 Broadcom.
 */

#include <crc32.h>
#include <drivers/bcm/bnxt.h>
#include <mm/core_mmu.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/*
 * These macros are the offsets where images reside on sec mem
 */
#define BNXT_BUFFER_SEC_MEM	0x8ae00000
#define BNXT_FW_SEC_MEM_SRC	BNXT_BUFFER_SEC_MEM
#define BNXT_FW_SEC_MEM_CFG	(BNXT_BUFFER_SEC_MEM + 0x100000)
#define TEMP_MEM		(BNXT_BUFFER_SEC_MEM + 0x180000)

#define BNXT_CRASH_SEC_MEM	0x8b000000
#define BNXT_CRASH_LEN		0x2000000

#define BNXT_CONFIG_NS3_DEST	0x03a00000
#define BNXT_BSPD_CFG_OFFSET	0x51b0
#define BNXT_CONFIG_NS3_BSPD_DEST	(BNXT_CONFIG_NS3_DEST + \
					 BNXT_BSPD_CFG_OFFSET)
#define BNXT_BSPD_CFG_SIZE	0x200

#define BNXT_CRASH_DUMP_INFO_NS3_BASE	0x3a5ff00

#define IS_ALIGNED(addr, algn)      (!((addr) & ((algn) - 1)))

#define SZ_1K				0x400

#define BUFFER_PADDING			SZ_1K

#define INC_SRC_ADDR			1

#define EOF				-1

#define BCM_BNXT_FASTBOOT_MASK		0x3u
#define BCM_BNXT_FASTBOOT_TYPE_1	1

#define ADDR_IS_4BYTE_ALIGNED(addr)	IS_ALIGNED(addr, 4)

#define SECTION_IS_LOADABLE(section_ptr) \
	((section_ptr)->flags_src_offset & SECTION_FLAGS_IS_LOADABLE)
#define SECTION_IS_ZIPPED(section_ptr) \
	((section_ptr)->flags_src_offset & SECTION_FLAGS_IS_ZIPPED)
#define SECTION_IS_TOBE_COPIED(section_ptr) \
	((section_ptr)->flags_src_offset & \
	 (SECTION_FLAGS_IS_EXEC_INSTR | SECTION_FLAGS_IS_DATA))
#define SECTION_IS_TOBE_ZEROED(section_ptr) \
	((section_ptr)->flags_src_offset & SECTION_FLAGS_IS_BSS)
#define SECTION_IS_4BYTE_ALIGNED(section_ptr) \
	ADDR_IS_4BYTE_ALIGNED((section_ptr)->dest_addr)

#define SECTION_SRC_OFFSET(section_ptr) \
	((section_ptr)->flags_src_offset & SECTION_SRC_OFFFSET_MASK)

/* -------------------------------------------------------------------------- */

/* Section header for each image block */
struct ape_section_hdr_s {
	/* Destination address that this section is to be copied to */
	uint32_t dest_addr;

	/*
	 * bit[0:23]  source offset address that this image copy from
	 * bit[24:31] flags
	 */
	uint32_t flags_src_offset;
#define SECTION_FLAGS_MASK		0xff000000
	/* Session is compressed (zipped) */
#define SECTION_FLAGS_IS_ZIPPED		0x01000000
	/* Session contains CRC */
#define SECTION_FLAGS_IS_CRC		0x02000000
	/* Session contains executable code (e.g. .text) */
#define SECTION_FLAGS_IS_EXEC_INSTR	0x04000000
	/* Session contains initialized data (e.g. .data) */
#define SECTION_FLAGS_IS_DATA		0x08000000
	/* Session contains zero initialized data (e.g. .bss) */
#define SECTION_FLAGS_IS_BSS		0x10000000
	/* Loadable section mask */
#define SECTION_FLAGS_IS_LOADABLE	(SECTION_FLAGS_IS_EXEC_INSTR | \
					 SECTION_FLAGS_IS_DATA | \
					 SECTION_FLAGS_IS_BSS)
#define SECTION_SRC_OFFFSET_MASK	0x00ffffff

	/* Original image length, dword (4byte) length */
	uint32_t org_data_len;

	/* Compressed image length (if FlAGS_IS_ZIPPED is set) */
	uint32_t zip_data_len;

	/*
	 * checksum value for this image block, if FLAGS_IS_CRC then
	 * this is CRC checksum; otherwise it is a simple summation
	 */
	uint32_t checksum;
};

struct version_s {
	uint8_t version[16];	/* Null-terminated file version string */
};

struct ver_ext_offset_s {
	uint8_t  version[12];	/* Null-terminated file version string */
	uint32_t ext_hdr_offset;
};

union version_and_offset_u {
	struct version_s version1;
	struct ver_ext_offset_s	version2;
};

struct ape_bin_hdr_s {
	/* APE binary header signature; expects APE_BIN_HDR_SIGNATURE */
	uint32_t signature;
#define APE_BIN_HDR_SIGNATURE 0x1a4d4342 /* "BCM"+0x1a */
	/* Reserved for ChiMP's use */
	uint8_t flags;
	uint8_t code_type;
	uint8_t device;
	uint8_t media;
	union version_and_offset_u ver;
	uint8_t build;
	uint8_t revision;
	uint8_t minor_ver;
	uint8_t major_ver;
	uint32_t entry_address;
	uint8_t reserved;
	uint8_t header_dword_size;
	uint8_t num_total_sections;
	uint8_t num_loadable_sections;
	uint32_t checksum;
} __packed __aligned(1);

#define APE_BIN_HDR_SIZE	sizeof(struct ape_bin_hdr_s)
#define APE_SECTION_HDR_SIZE	sizeof(struct ape_section_hdr_s)

/* MAX number of image sections that will be accepted */
#define APE_IMG_MAX_SECTIONS	16

#define APE_IMG_LOAD_DEBUG	0

/* -------------------------------------------------------------------------- */

struct ape_mem_region_s {
	uint32_t c_base;	/* ChiMP's view of address */
	uint32_t h_base;	/* Host's view of address */
	uint32_t size;		/* Size in bytes */
};

/* Memory map into various scratchpad memories */
static struct ape_mem_region_s ape_mem_regions[] = {
	/* CHIMP scratchpad */
	{0x00100000, 0x03100000, 1024 * SZ_1K},

	/* APE scratchpad */
	{0x61000000, 0x03300000, 1152 * SZ_1K},

	/* BONO scratchpad */
	{0x61600000, 0x03a00000, 512 * SZ_1K},

	/* KONG scratchpad */
	{0x61400000, 0x03800000, 512 * SZ_1K},

	/* Keep this last!! */
	{0, 0, 0}
};

/* Nitro crash address configuration related macros */
#define BNXT_CRASH_INFO_SIGNATURE 0x20524444
#define BNXT_CRASH_INFO_VALID 0x1
#define MAX_CRASH_ADDR_ITEM 8

struct nitro_crash_addr_item {
	uint32_t info;
	uint32_t size;
	uint32_t addr_hi;
	uint32_t addr_lo;
};

struct nitro_crash_addr_info {
	/* CRC of the struct content, starting at next field. */
	uint32_t crc;
	uint32_t signature;
	uint32_t version;
	struct nitro_crash_addr_item table[MAX_CRASH_ADDR_ITEM];
};

static inline void memcpy32_helper(uintptr_t src,
				   uintptr_t dst,
				   uint32_t entries,
				   int inc_src_addr)
{
	uint32_t copied_entries = 0;

	while (entries) {
		copied_entries = bnxt_write32_multiple(dst, src, entries,
						       inc_src_addr);

		if (copied_entries < entries) {
			dst += copied_entries * sizeof(uint32_t);
			src += (inc_src_addr) ?
				(copied_entries * sizeof(uint32_t)) : 0;
			entries -= copied_entries;
		} else {
			entries = 0;
		}
	}
}

static uint32_t ape_host_view_addr_get(uint32_t bnxt_view_addr, uint32_t size)
{
	struct ape_mem_region_s *region = ape_mem_regions;
	uint32_t addr = 0;

	for (; region->size != 0; region++) {
		if (bnxt_view_addr < region->c_base)
			continue;

		if (bnxt_view_addr >= (region->c_base + region->size))
			continue;

		if (size > (region->c_base + region->size - bnxt_view_addr)) {
			EMSG("ERROR: 0x%x + 0x%x spans memory boundary",
			     bnxt_view_addr, size);
			break;
		}

		addr = bnxt_view_addr - region->c_base;
		addr += region->h_base;
		break;
	}

	return addr;
}

static uint32_t ape_hdr_crc_calc(const struct ape_bin_hdr_s *hdr)
{
	uint32_t crc = 0;
	uint32_t dummy = 0;

	/* Compute the CRC up to, but not including, the checksum field */
	crc = CRC32(CRC32_INIT_VAL,
		    (const char *)hdr,
		    (uintptr_t)(&hdr->checksum) - (uintptr_t)hdr);

	/* Compute the CRC with the checksum field zeroed out */
	crc = CRC32(~crc, (const char *)&dummy, sizeof(uint32_t));

	/*
	 * Compute the remainder part of the image header, i.e., the
	 * section headers
	 */
	crc = CRC32(~crc,
		    (const char *)((uintptr_t)hdr + APE_BIN_HDR_SIZE),
		    hdr->num_total_sections * APE_SECTION_HDR_SIZE);

	return crc;
}

static int ape_bin_hdr_valid(const struct ape_bin_hdr_s *hdr)
{
	uint32_t checksum = 0;

	if (!hdr) {
		EMSG("ERROR: no APE image header");
		return BNXT_FAILURE;
	}

	if (hdr->signature != APE_BIN_HDR_SIGNATURE) {
		EMSG("ERROR: bad APE image signature");
		return BNXT_FAILURE;
	}

	if (hdr->num_total_sections > APE_IMG_MAX_SECTIONS) {
		EMSG("ERROR: too many sections in APE image");
		return BNXT_FAILURE;
	}

	checksum = ape_hdr_crc_calc(hdr);
	if (hdr->checksum != checksum) {
		EMSG("ERROR: bad APE header checksum (exp: %x, act: %x)",
		     hdr->checksum, checksum);
		return BNXT_FAILURE;
	}

	return BNXT_SUCCESS;
}

static int get_char(uint8_t *inbuf, size_t *inbuf_idx, size_t inbuf_size)
{
	int c = 0;

	if (*inbuf_idx >= inbuf_size)
		return EOF;

	c = inbuf[*inbuf_idx];
	*inbuf_idx += 1;

	return c;
}

static void put_char(uint8_t *outbuf,
		     size_t *outbuf_idx,
		     size_t outbuf_size,
		     uint8_t ch)
{
	if (*outbuf_idx >= outbuf_size)
		return;

	outbuf[*outbuf_idx] = ch;
	*outbuf_idx += 1;
}

static size_t ape_section_uncompress(uint8_t *inbuf,
				     size_t inbuf_size,
				     uint8_t *outbuf,
				     size_t outbuf_size)
{
	int i = 0, j = 0, k = 0, r = 0, c = 0;
	uint32_t flags = 0;
	size_t exp_size = 0, codesize = 0;
	size_t inbuf_idx = 0, outbuf_idx = 0;
#define CODE_8U_MASK		0xff00u	/* 8 code units count mask (8 bits) */
#define CODE_END_MASK		0x100u	/* End of code units mask */
#define CODE_IS_UNENCODED_MASK	1	/* Unencoded code unit mask */
#define CODE_POS_MASK		0xe0u	/* Encoded unit position mask and */
#define CODE_POS_SHIFT		3	/* Bit shift */
#define CODE_LEN_MASK		0x1fu	/* Encoded unit length mask */
#define NS			2048	/* Size of ring buffer */
#define F			34	/* Upper limit for match_length */
#define THRESHOLD		2	/* Encode string into position and
					 *   length, if match_length is
					 *   greater than this.
					 */
	/*
	 * Ring buffer of size NS, with an extra F-1 bytes to facilitate
	 * string comparisons.
	 */
	uint8_t text_buf[NS + F - 1];

	inbuf_idx = 0;
	outbuf_idx = 0;

	for (i = 0; i < NS - F; i++)
		text_buf[i] = ' ';

	r = NS - F;

	for (;;) {
		if (((flags >>= 1) & CODE_END_MASK) == 0) {
			c = get_char(inbuf, &inbuf_idx, inbuf_size);
			if (c == EOF)
				break;
			++exp_size;

			if (exp_size > inbuf_size)
				break;

			/* Use higher byte cleverly to count to eight */
			flags = c | CODE_8U_MASK;
		}

		if (flags & CODE_IS_UNENCODED_MASK) {
			/* Not encoded; simply copy the unit */
			c = get_char(inbuf, &inbuf_idx, inbuf_size);
			if (c == EOF)
				break;

			++exp_size;
			if (exp_size > inbuf_size)
				break;

			put_char(outbuf, &outbuf_idx, outbuf_size, c);
			text_buf[r++] = c;
			r &= (NS - 1);
			++codesize;
		} else {
			/* Encoded; get the position and length & duplicate */
			i = get_char(inbuf, &inbuf_idx, inbuf_size);
			if (i == EOF)
				break;

			++exp_size;
			if (exp_size > inbuf_size)
				break;

			j = get_char(inbuf, &inbuf_idx, inbuf_size);
			if (j == EOF)
				break;

			++exp_size;
			if (exp_size > inbuf_size)
				break;

			i |= ((j & CODE_POS_MASK) << CODE_POS_SHIFT);
			j = ((j & CODE_LEN_MASK) + THRESHOLD);

			for (k = 0; k <= j; k++) {
				c = text_buf[((i + k) & (NS - 1))];
				put_char(outbuf, &outbuf_idx, outbuf_size, c);
				text_buf[r++] = c;
				r &= (NS - 1);
				++codesize;
			}
		}
	}

	return codesize;
}

static int ape_section_copy(struct ape_bin_hdr_s *bin_hdr,
			    struct ape_section_hdr_s *section)
{
	uintptr_t src = 0;
	uintptr_t dst = 0;
	uint32_t checksum = 0;
	uint32_t i = 0;
	size_t size = 0;
	uint8_t *section_data = NULL;
	size_t work_buff_size = 0;
	void *work_buff = NULL;
	int rc = BNXT_FAILURE;

	if (SECTION_IS_ZIPPED(section)) {
		work_buff_size = section->org_data_len + BUFFER_PADDING;
		work_buff = (void *)phys_to_virt(TEMP_MEM, MEM_AREA_RAM_SEC,
						 work_buff_size);
		if (!work_buff) {
			EMSG("ERROR: buffer allocation");
			return BNXT_FAILURE;
		}

		section_data = (uint8_t *)((uintptr_t)bin_hdr +
					   SECTION_SRC_OFFSET(section));
		size = ape_section_uncompress(section_data,
					      section->zip_data_len,
					      work_buff,
					      work_buff_size);
		if (size >= work_buff_size) {
			EMSG("ERROR: section uncompress");
			goto ape_section_copy_exit;
		}
		if (size < section->org_data_len) {
			EMSG("ERROR: decompressed data size mismatch ");
			EMSG("(exp: %d, act: %ld)",
			     section->org_data_len, size);
			goto ape_section_copy_exit;
		}
		src = (uintptr_t)work_buff;
	} else {
		src = (uintptr_t)bin_hdr + SECTION_SRC_OFFSET(section);
	}

	size = section->org_data_len;

	if (section->flags_src_offset & SECTION_FLAGS_IS_CRC) {
		checksum = CRC32(CRC32_INIT_VAL, (const char *)src, size);
	} else {
		checksum = 0;
		for (i = 0; i < size / sizeof(uint32_t); i++)
			checksum += ((uint32_t *)src)[i];
	}
	if (checksum != section->checksum) {
		EMSG("ERROR: checksum mismatch (exp: %x, act: %x)",
		     section->checksum, checksum);
		goto ape_section_copy_exit;
	}

	dst = ape_host_view_addr_get(section->dest_addr, size);
	if (dst == 0) {
		EMSG("ERROR: ChiMP-to-host address conversion of %x",
		     section->dest_addr);
		goto ape_section_copy_exit;
	}

	/* Copy the section */
	size = size / sizeof(uint32_t);
	memcpy32_helper(src, dst, size, INC_SRC_ADDR);

	rc = BNXT_SUCCESS;

ape_section_copy_exit:
	return rc;
}

static int ape_section_zero(struct ape_section_hdr_s *section)
{
	uint32_t dst = 0;
	uint32_t size = section->org_data_len;
	uint32_t zero = 0;

	if (section->org_data_len == 0)
		return BNXT_SUCCESS;

	/* Convert ChiMP's view of the address in the image to the host view */
	dst = ape_host_view_addr_get(section->dest_addr, size);
	if (dst == 0) {
		EMSG("ERROR: ChiMP-to-host address conversion of %x",
		     section->dest_addr);
		return BNXT_FAILURE;
	}

	/*
	 * Zero the section; we simply copy zeros and do not increment the
	 * source buffer address.
	 */
	size = size / sizeof(uint32_t);
	memcpy32_helper((uintptr_t)&zero, dst, size, !INC_SRC_ADDR);

	return BNXT_SUCCESS;
}

static int bnxt_load(vaddr_t img_buffer)
{
	struct ape_bin_hdr_s *bin_hdr = NULL;
	struct ape_section_hdr_s *section = NULL;
	int sidx = 0;
	int rc = BNXT_SUCCESS;

	bin_hdr = (struct ape_bin_hdr_s *)img_buffer;
	section = (struct ape_section_hdr_s *)(img_buffer +
					       APE_BIN_HDR_SIZE);

	if (ape_bin_hdr_valid(bin_hdr) != BNXT_SUCCESS)
		return BNXT_FAILURE;

	for (sidx = 0; sidx < bin_hdr->num_total_sections; sidx++, section++) {
		if (!SECTION_IS_LOADABLE(section))
			continue;

		if (!ADDR_IS_4BYTE_ALIGNED(section->dest_addr)) {
			EMSG("ERROR: unaligned section dest address 0x%x",
			     section->dest_addr);
			rc = BNXT_FAILURE;
			break;
		}

		if (!ADDR_IS_4BYTE_ALIGNED(SECTION_SRC_OFFSET(section))) {
			EMSG("ERROR: unaligned section src offset (0x%x)",
			     SECTION_SRC_OFFSET(section));
			rc = BNXT_FAILURE;
			break;
		}

		if (section->org_data_len % sizeof(uint32_t)) {
			EMSG("ERROR: section size (%d) not divisible by 4",
			     section->org_data_len);
			rc = BNXT_FAILURE;
			break;
		}

		if (SECTION_IS_TOBE_COPIED(section)) {
			rc = ape_section_copy(bin_hdr, section);
			if (rc != BNXT_SUCCESS)
				break;
		} else if (SECTION_IS_TOBE_ZEROED(section)) {
			rc = ape_section_zero(section);
			if (rc != BNXT_SUCCESS)
				break;
		}
	}

	/* Set up boot mode and take BNXT out of reset */
	if (rc == BNXT_SUCCESS) {
		bnxt_fastboot((bin_hdr->entry_address &
			       ~BCM_BNXT_FASTBOOT_MASK) |
			       BCM_BNXT_FASTBOOT_TYPE_1);
	}

	return rc;
}

static TEE_Result bnxt_crash_config(uintptr_t info_dst,
				    uint32_t crash_area_start,
				    uint32_t crash_len)
{
	struct nitro_crash_addr_item *item = NULL;
	uintptr_t dst = 0;
	struct nitro_crash_addr_info *info = NULL;
	uintptr_t src = 0;
	uint32_t crc = 0;
	size_t size = 0;

	/*
	 * First we write into local memory to calculate CRC before
	 * updating into Nitro memory
	 */
	info = malloc(sizeof(struct nitro_crash_addr_info));
	if (!info) {
		EMSG("ERROR: buffer allocation");
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	memset(info, 0, sizeof(struct nitro_crash_addr_info));

	info->signature = BNXT_CRASH_INFO_SIGNATURE;
	info->version = 0x01000000 | MAX_CRASH_ADDR_ITEM;

	/* As of now only one item is filled */
	item = &info->table[0];
	item->info = 0;
	item->size = crash_len | BNXT_CRASH_INFO_VALID;
	item->addr_hi = 0;
	item->addr_lo = crash_area_start;

	/* Checksum calculation  */
	crc = CRC32(CRC32_INIT_VAL,
		    (const char *)info + sizeof(uint32_t),
		     sizeof(struct nitro_crash_addr_info) - sizeof(uint32_t));
	info->crc = crc;

	/* First we write the contents and then set valid bit */
	item->size &= ~BNXT_CRASH_INFO_VALID;

	size = sizeof(struct nitro_crash_addr_info) / sizeof(uint32_t);
	dst = info_dst;
	src = (uintptr_t)info;
	memcpy32_helper(src, dst, size, INC_SRC_ADDR);

	/* Set the valid bit */
	item->size |= BNXT_CRASH_INFO_VALID;
	dst = info_dst + offsetof(struct nitro_crash_addr_info, table) +
	      offsetof(struct nitro_crash_addr_item, size);
	bnxt_write32_multiple(dst, (uintptr_t)&item->size, 1, 1);

	free(info);

	return TEE_SUCCESS;
}

TEE_Result bnxt_load_fw(int chip_type)
{
	uint32_t size = 0;
	uintptr_t dst = 0;
	uintptr_t src = 0;
	struct bnxt_images_info bnxt_src_image_info;
	vaddr_t sec_mem_dest = (vaddr_t)phys_to_virt(BNXT_BUFFER_SEC_MEM,
						     MEM_AREA_RAM_SEC, 1);

	memset(&bnxt_src_image_info, 0, sizeof(struct bnxt_images_info));

	if (get_bnxt_images_info(&bnxt_src_image_info,
				 chip_type, sec_mem_dest) != BNXT_SUCCESS)
		return TEE_ERROR_ITEM_NOT_FOUND;

	bnxt_handshake_clear();
	bnxt_kong_halt();
	bnxt_chimp_halt();

	/* Copy the configs */
	src = (uintptr_t)bnxt_src_image_info.bnxt_cfg_vaddr;
	dst = (uintptr_t)BNXT_CONFIG_NS3_DEST;
	size = bnxt_src_image_info.bnxt_cfg_len;
	size = size / sizeof(uint32_t);
	memcpy32_helper(src, dst, size, INC_SRC_ADDR);

	/* Copy bspd config */
	src = (uintptr_t)bnxt_src_image_info.bnxt_bspd_cfg_vaddr;
	size = bnxt_src_image_info.bnxt_bspd_cfg_len;
	dst = (uintptr_t)BNXT_CONFIG_NS3_BSPD_DEST;

	size = size / sizeof(uint32_t);
	memcpy32_helper(src, dst, size, INC_SRC_ADDR);

	/* Fill the bnxt crash dump info */
	bnxt_crash_config((uintptr_t)BNXT_CRASH_DUMP_INFO_NS3_BASE,
			  BNXT_CRASH_SEC_MEM,
			  BNXT_CRASH_LEN);

	/* Load bnxt firmware and fastboot */
	bnxt_load(bnxt_src_image_info.bnxt_fw_vaddr);

	return TEE_SUCCESS;
}

TEE_Result bnxt_copy_crash_dump(uint8_t *d, uint32_t offset, uint32_t len)
{
	size_t crash_len = 0;
	void *s = NULL;

	if (ADD_OVERFLOW(offset, len, &crash_len) ||
	    crash_len > BNXT_CRASH_LEN)
		return TEE_ERROR_BAD_PARAMETERS;

	s = phys_to_virt(BNXT_CRASH_SEC_MEM + offset, MEM_AREA_RAM_SEC, len);

	cache_op_inner(DCACHE_AREA_INVALIDATE, s, len);

	memcpy(d, s, len);

	return TEE_SUCCESS;
}
