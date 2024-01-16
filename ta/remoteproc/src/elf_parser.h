/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2023, STMicroelectronics
 */

#ifndef ELF_PARSER_H
#define ELF_PARSER_H

#include <elf32.h>
#include <stdint.h>
#include <tee_api_types.h>

/**
 * struct resource_table - firmware resource table header
 * @ver: version number
 * @num: number of resource entries
 * @reserved: reserved (must be zero)
 * @offset: array of offsets pointing at the various resource entries
 *
 * A resource table is essentially a list of system resources required
 * by the remote processor. It may also include configuration entries.
 * If needed, the remote processor firmware should contain this table
 * as a dedicated ".resource_table" ELF section.
 *
 * This structure shall be consistent with the Linux kernel structure
 * definition from include/linux/remoteproc.h.
 *
 * The resource_table structure does not need to be packed in OP-TEE. The ELF
 * parser does not access the system resources structures that follow this
 * structure in shared memory (no memory alignment constraint on structures).
 */
struct resource_table {
	uint32_t ver;
	uint32_t num;
	uint32_t reserved[2];
	uint32_t offset[];
};

struct fw_elf32 {
	uintptr_t e_entry;
	uintptr_t e_phoff;
	uintptr_t e_shoff;
	uint32_t e_phnum;
	uint32_t e_shnum;
	uint32_t e_phentsize;
	uint32_t e_shentsize;

	Elf32_Phdr *phdr;
	Elf32_Shdr *shdr;
};

/*
 * e32_parse_ehdr() - Check and parse the ELF header
 *
 * @fw:   Firmware ELF file image
 * @size: Byte size of firmware ELF file image
 * Return TEE_SUCCESS or appropriate error.
 */
TEE_Result e32_parse_ehdr(uint8_t *fw, size_t size);

/*
 * e32_parser_load_elf_image() - simple ELF loader
 * @fw:		Firmware ELF file image
 * @fw_size:	Firmware ELF file image byte size
 * @load_seg:	Callback for loading a firmware image segment into device memory
 * @priv_data:	Private data passed to @load_seg callback.
 * Return TEE_SUCCESS or appropriate error.
 */
TEE_Result e32_parser_load_elf_image(uint8_t *fw, size_t fw_size,
				     TEE_Result (*load_seg)(uint8_t *src,
							    uint32_t size,
							    uint32_t da,
							    uint32_t mem_size,
							    void *priv),
				     void *priv_data);

/*
 * e32_parser_find_rsc_table() - find resource table in an ELF image
 * @fw:		Firmware ELF file image
 * @fw_size:	Firmware ELF file image byte size
 * @rsc_addr:	Output resource table address from the remote proc perspective
 * @rsc_size:	Output resource table size
 * Return TEE_SUCCESS if found,
 *        TEE_ERROR_NO_DATA if not found,
 *        or appropriate error.
 */
TEE_Result e32_parser_find_rsc_table(uint8_t *fw, size_t fw_size,
				     Elf32_Addr *rsc_addr,
				     Elf32_Word *rsc_size);

#endif /*ELF_PARSER_H*/
