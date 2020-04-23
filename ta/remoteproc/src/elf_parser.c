// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2023, STMicroelectronics
 */

#include <assert.h>
#include <elf_parser.h>
#include <string.h>
#include <trace.h>
#include <types_ext.h>
#include <util.h>

static bool va_in_fwm_image_range(void *va, uint8_t *fw, size_t fw_size)
{
	uint8_t *vaddr = va;

	return vaddr >= fw && vaddr < fw + fw_size;
}

TEE_Result e32_parse_ehdr(uint8_t *fw, size_t size)
{
	Elf32_Ehdr *ehdr = (Elf32_Ehdr *)(void *)fw;

	if (!fw || !IS_ALIGNED_WITH_TYPE(fw, uint32_t)) {
		EMSG("Invalid firmware address");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (size < sizeof(Elf32_Ehdr) ||
	    size < (ehdr->e_shoff + sizeof(Elf32_Shdr)))
		return TEE_ERROR_BAD_FORMAT;

	if (!IS_ELF(*ehdr) ||
	    ehdr->e_ident[EI_VERSION] != EV_CURRENT ||
	    ehdr->e_ident[EI_CLASS] != ELFCLASS32 ||
	    ehdr->e_phentsize != sizeof(Elf32_Phdr) ||
	    ehdr->e_shentsize != sizeof(Elf32_Shdr)) {
		EMSG("Invalid header");
		return TEE_ERROR_BAD_FORMAT;
	}

	if (ehdr->e_phnum == 0) {
		EMSG("No loadable segment found");
		return TEE_ERROR_BAD_FORMAT;
	}

	return TEE_SUCCESS;
}

TEE_Result e32_parser_load_elf_image(uint8_t *fw, size_t fw_size,
				     TEE_Result (*load_seg)(uint8_t *src,
							    uint32_t size,
							    uint32_t da,
							    uint32_t mem_size,
							    void *priv),
				     void *priv_data)
{
	Elf32_Ehdr *ehdr = (Elf32_Ehdr *)(void *)fw;
	Elf32_Phdr *phdr = (void *)((int8_t *)ehdr + ehdr->e_phoff);
	TEE_Result res = TEE_SUCCESS;
	unsigned int i = 0;

	if (!load_seg || fw + fw_size <= fw)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!IS_ALIGNED_WITH_TYPE(phdr, uint32_t) ||
	    !va_in_fwm_image_range(phdr, fw, fw_size))
		return TEE_ERROR_BAD_FORMAT;

	for (i = 0; i < ehdr->e_phnum; i++, phdr++) {
		uint32_t dst = phdr->p_paddr;
		uint8_t *src = NULL;

		if (phdr->p_type != PT_LOAD)
			continue;

		if (!va_in_fwm_image_range((void *)((vaddr_t)(phdr + 1) - 1),
					   fw, fw_size))
			return TEE_ERROR_BAD_FORMAT;

		src = (uint8_t *)fw + phdr->p_offset;

		if (!va_in_fwm_image_range(src, fw, fw_size) ||
		    !va_in_fwm_image_range(src + phdr->p_filesz, fw, fw_size))
			return TEE_ERROR_BAD_FORMAT;

		res = load_seg(src, phdr->p_filesz, dst, phdr->p_memsz,
			       priv_data);
		if (res)
			return res;
	}

	return TEE_SUCCESS;
}

TEE_Result e32_parser_find_rsc_table(uint8_t *fw, size_t fw_size,
				     Elf32_Addr *rsc_addr,
				     Elf32_Word *rsc_size)
{
	Elf32_Shdr *shdr = NULL;
	unsigned int i = 0;
	char *name_table = NULL;
	struct resource_table *table = NULL;
	Elf32_Ehdr *ehdr = (Elf32_Ehdr *)(void *)fw;
	uint8_t *elf_data = fw;

	if (fw + fw_size <= fw || fw + ehdr->e_shoff < fw)
		return TEE_ERROR_BAD_PARAMETERS;

	shdr = (void *)(fw + ehdr->e_shoff);
	if (!IS_ALIGNED_WITH_TYPE(shdr, uint32_t) ||
	    !va_in_fwm_image_range(shdr, fw, fw_size))
		return TEE_ERROR_BAD_FORMAT;

	name_table = (char *)elf_data + shdr[ehdr->e_shstrndx].sh_offset;
	if (!va_in_fwm_image_range(name_table, fw, fw_size))
		return TEE_ERROR_BAD_FORMAT;

	for (i = 0; i < ehdr->e_shnum; i++, shdr++) {
		size_t size = shdr->sh_size;
		size_t offset = shdr->sh_offset;
		size_t s = 0;

		if (!va_in_fwm_image_range(shdr, fw, fw_size))
			return TEE_ERROR_BAD_FORMAT;

		if (strcmp(name_table + shdr->sh_name, ".resource_table"))
			continue;

		if (!shdr->sh_size)
			return TEE_ERROR_NO_DATA;

		if (offset + size > fw_size || offset + size < size) {
			EMSG("Resource table truncated");
			return TEE_ERROR_BAD_FORMAT;
		}

		if (sizeof(struct resource_table) > size) {
			EMSG("No header found in resource table");
			return TEE_ERROR_BAD_FORMAT;
		}

		table = (struct resource_table *)(void *)(elf_data + offset);
		if (!IS_ALIGNED_WITH_TYPE(table, uint32_t))
			return TEE_ERROR_CORRUPT_OBJECT;

		if (table->ver != 1) {
			EMSG("Unsupported firmware version %"PRId32,
			     table->ver);
			return TEE_ERROR_BAD_FORMAT;
		}

		if (table->reserved[0] || table->reserved[1]) {
			EMSG("Non zero reserved bytes");
			return TEE_ERROR_BAD_FORMAT;
		}

		if (MUL_OVERFLOW(table->num, sizeof(*table->offset), &s) ||
		    ADD_OVERFLOW(s, sizeof(struct resource_table), &s) ||
		    s > size) {
			EMSG("Resource table incomplete");
			return TEE_ERROR_BAD_FORMAT;
		}

		DMSG("Resource table address %#"PRIx32", size %"PRIu32,
		     shdr->sh_addr, shdr->sh_size);

		*rsc_addr = shdr->sh_addr;
		*rsc_size = shdr->sh_size;

		return TEE_SUCCESS;
	}

	return TEE_ERROR_NO_DATA;
}
