// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2019, Linaro Limited
 */

#include <assert.h>
#include <ctype.h>
#include <elf32.h>
#include <elf64.h>
#include <elf_common.h>
#include <ldelf.h>
#include <pta_system.h>
#include <stdio.h>
#include <stdlib.h>
#include <string_ext.h>
#include <string.h>
#include <tee_api_types.h>
#include <user_ta_header.h>
#include <utee_syscalls.h>

#include "sys.h"
#include "ta_elf.h"
#include "unwind.h"

static vaddr_t ta_stack;
static vaddr_t ta_stack_size;

struct ta_elf_queue main_elf_queue = TAILQ_HEAD_INITIALIZER(main_elf_queue);

static struct ta_elf *queue_elf(const TEE_UUID *uuid)
{
	struct ta_elf *elf = NULL;

	TAILQ_FOREACH(elf, &main_elf_queue, link)
		if (!memcmp(uuid, &elf->uuid, sizeof(*uuid)))
			return NULL;

	elf = calloc(1, sizeof(*elf));
	if (!elf)
		err(TEE_ERROR_OUT_OF_MEMORY, "calloc");

	TAILQ_INIT(&elf->segs);

	elf->uuid = *uuid;
	TAILQ_INSERT_TAIL(&main_elf_queue, elf, link);
	return elf;
}

static TEE_Result e32_parse_ehdr(struct ta_elf *elf, Elf32_Ehdr *ehdr)
{
	if (ehdr->e_ident[EI_VERSION] != EV_CURRENT ||
	    ehdr->e_ident[EI_CLASS] != ELFCLASS32 ||
	    ehdr->e_ident[EI_DATA] != ELFDATA2LSB ||
	    ehdr->e_ident[EI_OSABI] != ELFOSABI_NONE ||
	    ehdr->e_type != ET_DYN || ehdr->e_machine != EM_ARM ||
	    (ehdr->e_flags & EF_ARM_ABIMASK) != EF_ARM_ABI_VERSION ||
#ifndef CFG_WITH_VFP
	    (ehdr->e_flags & EF_ARM_ABI_FLOAT_HARD) ||
#endif
	    ehdr->e_phentsize != sizeof(Elf32_Phdr) ||
	    ehdr->e_shentsize != sizeof(Elf32_Shdr))
		return TEE_ERROR_BAD_FORMAT;

	elf->is_32bit = true;
	elf->e_entry = ehdr->e_entry;
	elf->e_phoff = ehdr->e_phoff;
	elf->e_shoff = ehdr->e_shoff;
	elf->e_phnum = ehdr->e_phnum;
	elf->e_shnum = ehdr->e_shnum;
	elf->e_phentsize = ehdr->e_phentsize;
	elf->e_shentsize = ehdr->e_shentsize;

	return TEE_SUCCESS;
}

#ifdef ARM64
static TEE_Result e64_parse_ehdr(struct ta_elf *elf, Elf64_Ehdr *ehdr)
{
	if (ehdr->e_ident[EI_VERSION] != EV_CURRENT ||
	    ehdr->e_ident[EI_CLASS] != ELFCLASS64 ||
	    ehdr->e_ident[EI_DATA] != ELFDATA2LSB ||
	    ehdr->e_ident[EI_OSABI] != ELFOSABI_NONE ||
	    ehdr->e_type != ET_DYN || ehdr->e_machine != EM_AARCH64 ||
	    ehdr->e_flags || ehdr->e_phentsize != sizeof(Elf64_Phdr) ||
	    ehdr->e_shentsize != sizeof(Elf64_Shdr))
		return TEE_ERROR_BAD_FORMAT;


	elf->is_32bit = false;
	elf->e_entry = ehdr->e_entry;
	elf->e_phoff = ehdr->e_phoff;
	elf->e_shoff = ehdr->e_shoff;
	elf->e_phnum = ehdr->e_phnum;
	elf->e_shnum = ehdr->e_shnum;
	elf->e_phentsize = ehdr->e_phentsize;
	elf->e_shentsize = ehdr->e_shentsize;

	return TEE_SUCCESS;
}
#else /*ARM64*/
static TEE_Result e64_parse_ehdr(struct ta_elf *elf __unused,
				 Elf64_Ehdr *ehdr __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}
#endif /*ARM64*/

static void read_dyn(struct ta_elf *elf, vaddr_t addr,
		     size_t idx, unsigned int *tag, size_t *val)
{
	if (elf->is_32bit) {
		Elf32_Dyn *dyn = (Elf32_Dyn *)(addr + elf->load_addr);

		*tag = dyn[idx].d_tag;
		*val = dyn[idx].d_un.d_val;
	} else {
		Elf64_Dyn *dyn = (Elf64_Dyn *)(addr + elf->load_addr);

		*tag = dyn[idx].d_tag;
		*val = dyn[idx].d_un.d_val;
	}
}

static void e32_save_symtab(struct ta_elf *elf, size_t tab_idx)
{
	Elf32_Shdr *shdr = elf->shdr;
	size_t str_idx = shdr[tab_idx].sh_link;

	elf->dynsymtab = (void *)(shdr[tab_idx].sh_addr + elf->load_addr);
	assert(!(shdr[tab_idx].sh_size % sizeof(Elf32_Sym)));
	elf->num_dynsyms = shdr[tab_idx].sh_size / sizeof(Elf32_Sym);

	elf->dynstr = (void *)(shdr[str_idx].sh_addr + elf->load_addr);
	elf->dynstr_size = shdr[str_idx].sh_size;
}

static void e64_save_symtab(struct ta_elf *elf, size_t tab_idx)
{
	Elf64_Shdr *shdr = elf->shdr;
	size_t str_idx = shdr[tab_idx].sh_link;

	elf->dynsymtab = (void *)(vaddr_t)(shdr[tab_idx].sh_addr +
					   elf->load_addr);
	assert(!(shdr[tab_idx].sh_size % sizeof(Elf64_Sym)));
	elf->num_dynsyms = shdr[tab_idx].sh_size / sizeof(Elf64_Sym);

	elf->dynstr = (void *)(vaddr_t)(shdr[str_idx].sh_addr + elf->load_addr);
	elf->dynstr_size = shdr[str_idx].sh_size;
}

static void save_symtab(struct ta_elf *elf)
{
	size_t n = 0;

	if (elf->is_32bit) {
		Elf32_Shdr *shdr = elf->shdr;

		for (n = 0; n < elf->e_shnum; n++) {
			if (shdr[n].sh_type == SHT_DYNSYM) {
				e32_save_symtab(elf, n);
				break;
			}
		}
	} else {
		Elf64_Shdr *shdr = elf->shdr;

		for (n = 0; n < elf->e_shnum; n++) {
			if (shdr[n].sh_type == SHT_DYNSYM) {
				e64_save_symtab(elf, n);
				break;
			}
		}

	}
}

static void init_elf(struct ta_elf *elf)
{
	TEE_Result res = TEE_SUCCESS;
	vaddr_t va = 0;
	uint32_t flags = PTA_SYSTEM_MAP_FLAG_SHAREABLE;

	res = sys_open_ta_bin(&elf->uuid, &elf->handle);
	if (res)
		err(res, "sys_open_ta_bin(%pUl)", (void *)&elf->uuid);

	/*
	 * Map it read-only executable when we're loading a library where
	 * the ELF header is included in a load segment.
	 */
	if (!elf->is_main)
		flags |= PTA_SYSTEM_MAP_FLAG_EXECUTABLE;
	res = sys_map_ta_bin(&va, SMALL_PAGE_SIZE, flags, elf->handle, 0, 0, 0);
	if (res)
		err(res, "sys_map_ta_bin");
	elf->ehdr_addr = va;
	if (!elf->is_main) {
		elf->load_addr = va;
		elf->max_addr = va + SMALL_PAGE_SIZE;
		elf->max_offs = SMALL_PAGE_SIZE;
	}

	if (!IS_ELF(*(Elf32_Ehdr *)va))
		err(TEE_ERROR_BAD_FORMAT, "TA is not an ELF");

	res = e32_parse_ehdr(elf, (void *)va);
	if (res == TEE_ERROR_BAD_FORMAT)
		res = e64_parse_ehdr(elf, (void *)va);
	if (res)
		err(res, "Cannot parse ELF");

	if (elf->e_phoff + elf->e_phnum * elf->e_phentsize > SMALL_PAGE_SIZE)
		err(TEE_ERROR_NOT_SUPPORTED, "Cannot read program headers");

	elf->phdr = (void *)(va + elf->e_phoff);
}

static size_t roundup(size_t v)
{
	return ROUNDUP(v, SMALL_PAGE_SIZE);
}

static size_t rounddown(size_t v)
{
	return ROUNDDOWN(v, SMALL_PAGE_SIZE);
}

static void add_segment(struct ta_elf *elf, size_t offset, size_t vaddr,
			size_t filesz, size_t memsz, size_t flags, size_t align)
{
	struct segment *seg = calloc(1, sizeof(*seg));

	if (!seg)
		err(TEE_ERROR_OUT_OF_MEMORY, "calloc");

	seg->offset = offset;
	seg->vaddr = vaddr;
	seg->filesz = filesz;
	seg->memsz = memsz;
	seg->flags = flags;
	seg->align = align;

	TAILQ_INSERT_TAIL(&elf->segs, seg, link);
}

static void parse_load_segments(struct ta_elf *elf)
{
	size_t n = 0;

	if (elf->is_32bit) {
		Elf32_Phdr *phdr = elf->phdr;

		for (n = 0; n < elf->e_phnum; n++)
			if (phdr[n].p_type == PT_LOAD) {
				add_segment(elf, phdr[n].p_offset,
					    phdr[n].p_vaddr, phdr[n].p_filesz,
					    phdr[n].p_memsz, phdr[n].p_flags,
					    phdr[n].p_align);
			} else if (phdr[n].p_type == PT_ARM_EXIDX) {
				elf->exidx_start = phdr[n].p_vaddr;
				elf->exidx_size = phdr[n].p_filesz;
			}
	} else {
		Elf64_Phdr *phdr = elf->phdr;

		for (n = 0; n < elf->e_phnum; n++)
			if (phdr[n].p_type == PT_LOAD)
				add_segment(elf, phdr[n].p_offset,
					    phdr[n].p_vaddr, phdr[n].p_filesz,
					    phdr[n].p_memsz, phdr[n].p_flags,
					    phdr[n].p_align);
	}
}

static void copy_remapped_to(struct ta_elf *elf, const struct segment *seg)
{
	uint8_t *dst = (void *)(seg->vaddr + elf->load_addr);
	size_t n = 0;
	size_t offs = seg->offset;
	size_t num_bytes = seg->filesz;

	if (offs < elf->max_offs) {
		n = MIN(elf->max_offs - offs, num_bytes);
		memcpy(dst, (void *)(elf->max_addr + offs - elf->max_offs), n);
		dst += n;
		offs += n;
		num_bytes -= n;
	}

	if (num_bytes) {
		TEE_Result res = sys_copy_from_ta_bin(dst, num_bytes,
						      elf->handle, offs);

		if (res)
			err(res, "sys_copy_from_ta_bin");
		elf->max_offs += offs;
	}
}

static void adjust_segments(struct ta_elf *elf)
{
	struct segment *seg = NULL;
	struct segment *prev_seg = NULL;
	size_t prev_end_addr = 0;
	size_t align = 0;
	size_t mask = 0;

	/* Sanity check */
	TAILQ_FOREACH(seg, &elf->segs, link) {
		size_t dummy __maybe_unused = 0;

		assert(seg->align >= SMALL_PAGE_SIZE);
		assert(!ADD_OVERFLOW(seg->vaddr, seg->memsz, &dummy));
		assert(seg->filesz <= seg->memsz);
		assert((seg->offset & SMALL_PAGE_MASK) ==
		       (seg->vaddr & SMALL_PAGE_MASK));

		prev_seg = TAILQ_PREV(seg, segment_head, link);
		if (prev_seg) {
			assert(seg->vaddr >= prev_seg->vaddr + prev_seg->memsz);
			assert(seg->offset >=
			       prev_seg->offset + prev_seg->filesz);
		}
		if (!align)
			align = seg->align;
		assert(align == seg->align);
	}

	mask = align - 1;

	seg = TAILQ_FIRST(&elf->segs);
	if (seg)
		seg = TAILQ_NEXT(seg, link);
	while (seg) {
		prev_seg = TAILQ_PREV(seg, segment_head, link);
		prev_end_addr = prev_seg->vaddr + prev_seg->memsz;

		/*
		 * This segment may overlap with the last "page" in the
		 * previous segment in two different ways:
		 * 1. Virtual address (and offset) overlaps =>
		 *    Permissions needs to be merged. The offset must have
		 *    the SMALL_PAGE_MASK bits set as vaddr and offset must
		 *    add up with prevsion segment.
		 *
		 * 2. Only offset overlaps =>
		 *    The same page in the ELF is mapped at two different
		 *    virtual addresses. As a limitation this segment must
		 *    be mapped as writeable.
		 */

		/* Case 1. */
		if (rounddown(seg->vaddr) < prev_end_addr) {
			assert((seg->vaddr & mask) == (seg->offset & mask));
			assert(prev_seg->memsz == prev_seg->filesz);

			/*
			 * Merge the segments and their permissions.
			 * Note that the may be a small hole between the
			 * two sections.
			 */
			prev_seg->filesz = seg->vaddr + seg->filesz -
					   prev_seg->vaddr;
			prev_seg->memsz = seg->vaddr + seg->memsz -
					   prev_seg->vaddr;
			prev_seg->flags |= seg->flags;

			TAILQ_REMOVE(&elf->segs, seg, link);
			free(seg);
			seg = TAILQ_NEXT(prev_seg, link);
			continue;
		}

		/* Case 2. */
		if ((seg->offset & mask) &&
		    rounddown(seg->offset) <
		    (prev_seg->offset + prev_seg->filesz)) {

			assert(seg->flags & PF_W);
			seg->remapped_writeable = true;
		}

		/*
		 * No overlap, but we may need to align address, offset and
		 * size.
		 */
		seg->filesz += seg->vaddr - rounddown(seg->vaddr);
		seg->memsz += seg->vaddr - rounddown(seg->vaddr);
		seg->vaddr = rounddown(seg->vaddr);
		seg->offset = rounddown(seg->offset);
		seg = TAILQ_NEXT(seg, link);
	}

}

static void populate_segments_legacy(struct ta_elf *elf)
{
	TEE_Result res = TEE_SUCCESS;
	struct segment *seg = NULL;
	vaddr_t va = 0;

	TAILQ_FOREACH(seg, &elf->segs, link) {
		struct segment *last_seg = TAILQ_LAST(&elf->segs, segment_head);
		size_t pad_end = roundup(last_seg->vaddr + last_seg->memsz -
					 seg->vaddr - seg->memsz);
		size_t num_bytes = roundup(seg->memsz);

		if (!elf->load_addr)
			va = 0;
		else
			va = seg->vaddr + elf->load_addr;


		if (!(seg->flags & PF_R))
			err(TEE_ERROR_NOT_SUPPORTED,
			    "Segment must be readable");

		res = sys_map_zi(num_bytes, 0, &va, 0, pad_end);
		if (res)
			err(res, "sys_map_zi");
		res = sys_copy_from_ta_bin((void *)va, seg->filesz,
					   elf->handle, seg->offset);
		if (res)
			err(res, "sys_copy_from_ta_bin");

		if (!elf->load_addr)
			elf->load_addr = va;
		elf->max_addr = va + num_bytes;
		elf->max_offs = seg->offset + seg->filesz;
	}
}

static size_t get_pad_begin(void)
{
#ifdef CFG_TA_ASLR
	size_t min = CFG_TA_ASLR_MIN_OFFSET_PAGES;
	size_t max = CFG_TA_ASLR_MAX_OFFSET_PAGES;
	TEE_Result res = TEE_SUCCESS;
	uint32_t rnd32 = 0;
	size_t rnd = 0;

	COMPILE_TIME_ASSERT(CFG_TA_ASLR_MIN_OFFSET_PAGES <
			    CFG_TA_ASLR_MAX_OFFSET_PAGES);
	if (max > min) {
		res = utee_cryp_random_number_generate(&rnd32, sizeof(rnd32));
		if (res) {
			DMSG("Random read failed: %#"PRIx32, res);
			return min * SMALL_PAGE_SIZE;
		}
		rnd = rnd32 % (max - min);
	}

	return (min + rnd) * SMALL_PAGE_SIZE;
#else /*!CFG_TA_ASLR*/
	return 0;
#endif /*!CFG_TA_ASLR*/
}

static void populate_segments(struct ta_elf *elf)
{
	TEE_Result res = TEE_SUCCESS;
	struct segment *seg = NULL;
	vaddr_t va = 0;
	size_t pad_begin = 0;

	TAILQ_FOREACH(seg, &elf->segs, link) {
		struct segment *last_seg = TAILQ_LAST(&elf->segs, segment_head);
		size_t pad_end = roundup(last_seg->vaddr + last_seg->memsz -
					 seg->vaddr - seg->memsz);

		if (seg->remapped_writeable) {
			size_t num_bytes = roundup(seg->vaddr + seg->memsz) -
					   rounddown(seg->vaddr);

			assert(elf->load_addr);
			va = rounddown(elf->load_addr + seg->vaddr);
			assert(va >= elf->max_addr);
			res = sys_map_zi(num_bytes, 0, &va, 0, pad_end);
			if (res)
				err(res, "sys_map_zi");

			copy_remapped_to(elf, seg);
			elf->max_addr = va + num_bytes;
		} else {
			uint32_t flags =  0;
			size_t filesz = seg->filesz;
			size_t memsz = seg->memsz;
			size_t offset = seg->offset;
			size_t vaddr = seg->vaddr;

			if (offset < elf->max_offs) {
				/*
				 * We're in a load segment which overlaps
				 * with (or is covered by) the first page
				 * of a shared library.
				 */
				if (vaddr + filesz < SMALL_PAGE_SIZE) {
					size_t num_bytes = 0;

					/*
					 * If this segment is completely
					 * covered, take next.
					 */
					if (vaddr + memsz <= SMALL_PAGE_SIZE)
						continue;

					/*
					 * All data of the segment is
					 * loaded, but we need to zero
					 * extend it.
					 */
					va = elf->max_addr;
					num_bytes = roundup(vaddr + memsz) -
						    roundup(vaddr) -
						    SMALL_PAGE_SIZE;
					assert(num_bytes);
					res = sys_map_zi(num_bytes, 0, &va, 0,
							 0);
					if (res)
						err(res, "sys_map_zi");
					elf->max_addr = roundup(va + num_bytes);
					continue;
				}

				/* Partial overlap, remove the first page. */
				vaddr += SMALL_PAGE_SIZE;
				filesz -= SMALL_PAGE_SIZE;
				memsz -= SMALL_PAGE_SIZE;
				offset += SMALL_PAGE_SIZE;
			}

			if (!elf->load_addr) {
				va = 0;
				pad_begin = get_pad_begin();
				/*
				 * If mapping with pad_begin fails we'll
				 * retry without pad_begin, effectively
				 * disabling ASLR for the current ELF file.
				 */
			} else {
				va = vaddr + elf->load_addr;
				pad_begin = 0;
			}

			if (seg->flags & PF_W)
				flags |= PTA_SYSTEM_MAP_FLAG_WRITEABLE;
			else
				flags |= PTA_SYSTEM_MAP_FLAG_SHAREABLE;
			if (seg->flags & PF_X)
				flags |= PTA_SYSTEM_MAP_FLAG_EXECUTABLE;
			if (!(seg->flags & PF_R))
				err(TEE_ERROR_NOT_SUPPORTED,
				    "Segment must be readable");
			if (flags & PTA_SYSTEM_MAP_FLAG_WRITEABLE) {
				res = sys_map_zi(memsz, 0, &va, pad_begin,
						 pad_end);
				if (pad_begin && res == TEE_ERROR_OUT_OF_MEMORY)
					res = sys_map_zi(memsz, 0, &va, 0,
							 pad_end);
				if (res)
					err(res, "sys_map_zi");
				res = sys_copy_from_ta_bin((void *)va, filesz,
							   elf->handle, offset);
				if (res)
					err(res, "sys_copy_from_ta_bin");
			} else {
				res = sys_map_ta_bin(&va, filesz, flags,
						     elf->handle, offset,
						     pad_begin, pad_end);
				if (pad_begin && res == TEE_ERROR_OUT_OF_MEMORY)
					res = sys_map_ta_bin(&va, filesz, flags,
							     elf->handle,
							     offset, 0,
							     pad_end);
				if (res)
					err(res, "sys_map_ta_bin");
			}

			if (!elf->load_addr)
				elf->load_addr = va;
			elf->max_addr = roundup(va + filesz);
			elf->max_offs += filesz;
		}
	}
}

static void map_segments(struct ta_elf *elf)
{
	TEE_Result res = TEE_SUCCESS;

	parse_load_segments(elf);
	adjust_segments(elf);
	if (TAILQ_FIRST(&elf->segs)->offset < SMALL_PAGE_SIZE) {
		vaddr_t va = 0;
		size_t sz = elf->max_addr - elf->load_addr;
		struct segment *seg = TAILQ_LAST(&elf->segs, segment_head);
		size_t pad_begin = get_pad_begin();

		/*
		 * We're loading a library, if not other parts of the code
		 * need to be updated too.
		 */
		assert(!elf->is_main);

		/*
		 * Now that we know how much virtual memory is needed move
		 * the already mapped part to a location which can
		 * accommodate us.
		 */
		res = sys_remap(elf->load_addr, &va, sz, pad_begin,
				roundup(seg->vaddr + seg->memsz));
		if (res == TEE_ERROR_OUT_OF_MEMORY)
			res = sys_remap(elf->load_addr, &va, sz, 0,
					roundup(seg->vaddr + seg->memsz));
		if (res)
			err(res, "sys_remap");
		elf->ehdr_addr = va;
		elf->load_addr = va;
		elf->max_addr = va + sz;
		elf->phdr = (void *)(va + elf->e_phoff);
	}
	if (elf->is_legacy)
		populate_segments_legacy(elf);
	else
		populate_segments(elf);
}

static int hex(char c)
{
	char lc = tolower(c);

	if (isdigit(lc))
		return lc - '0';
	if (isxdigit(lc))
		return lc - 'a' + 10;
	return -1;
}

static uint32_t parse_hex(const char *s, size_t nchars, uint32_t *res)
{
	uint32_t v = 0;
	size_t n;
	int c;

	for (n = 0; n < nchars; n++) {
		c = hex(s[n]);
		if (c == (char)-1) {
			*res = TEE_ERROR_BAD_FORMAT;
			goto out;
		}
		v = (v << 4) + c;
	}
	*res = TEE_SUCCESS;
out:
	return v;
}

/*
 * Convert a UUID string @s into a TEE_UUID @uuid
 * Expected format for @s is: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
 * 'x' being any hexadecimal digit (0-9a-fA-F)
 */
static TEE_Result parse_uuid(const char *s, TEE_UUID *uuid)
{
	TEE_Result res = TEE_SUCCESS;
	TEE_UUID u = { 0 };
	const char *p = s;
	size_t i;

	if (strlen(p) != 36)
		return TEE_ERROR_BAD_FORMAT;
	if (p[8] != '-' || p[13] != '-' || p[18] != '-' || p[23] != '-')
		return TEE_ERROR_BAD_FORMAT;

	u.timeLow = parse_hex(p, 8, &res);
	if (res)
		goto out;
	p += 9;
	u.timeMid = parse_hex(p, 4, &res);
	if (res)
		goto out;
	p += 5;
	u.timeHiAndVersion = parse_hex(p, 4, &res);
	if (res)
		goto out;
	p += 5;
	for (i = 0; i < 8; i++) {
		u.clockSeqAndNode[i] = parse_hex(p, 2, &res);
		if (res)
			goto out;
		if (i == 1)
			p += 3;
		else
			p += 2;
	}
	*uuid = u;
out:
	return res;
}

static void add_deps_from_segment(struct ta_elf *elf, unsigned int type,
				  vaddr_t addr, size_t memsz)
{
	size_t dyn_entsize = 0;
	size_t num_dyns = 0;
	size_t n = 0;
	unsigned int tag = 0;
	size_t val = 0;
	TEE_UUID uuid = { };
	char *str_tab = NULL;

	if (type != PT_DYNAMIC)
		return;

	if (elf->is_32bit)
		dyn_entsize = sizeof(Elf32_Dyn);
	else
		dyn_entsize = sizeof(Elf64_Dyn);

	assert(!(memsz % dyn_entsize));
	num_dyns = memsz / dyn_entsize;

	for (n = 0; n < num_dyns; n++) {
		read_dyn(elf, addr, n, &tag, &val);
		if (tag == DT_STRTAB) {
			str_tab = (char *)(val + elf->load_addr);
			break;
		}
	}

	for (n = 0; n < num_dyns; n++) {
		read_dyn(elf, addr, n, &tag, &val);
		if (tag != DT_NEEDED)
			continue;
		parse_uuid(str_tab + val, &uuid);
		queue_elf(&uuid);
	}
}

static void add_dependencies(struct ta_elf *elf)
{
	size_t n = 0;

	if (elf->is_32bit) {
		Elf32_Phdr *phdr = elf->phdr;

		for (n = 0; n < elf->e_phnum; n++)
			add_deps_from_segment(elf, phdr[n].p_type,
					      phdr[n].p_vaddr, phdr[n].p_memsz);
	} else {
		Elf64_Phdr *phdr = elf->phdr;

		for (n = 0; n < elf->e_phnum; n++)
			add_deps_from_segment(elf, phdr[n].p_type,
					      phdr[n].p_vaddr, phdr[n].p_memsz);
	}
}

static void copy_section_headers(struct ta_elf *elf)
{
	TEE_Result res = TEE_SUCCESS;
	size_t sz = elf->e_shnum * elf->e_shentsize;
	size_t offs = 0;

	elf->shdr = malloc(sz);
	if (!elf->shdr)
		err(TEE_ERROR_OUT_OF_MEMORY, "malloc");

	/*
	 * We're assuming that section headers comes after the load segments,
	 * but if it's a very small dynamically linked library the section
	 * headers can still end up (partially?) in the first mapped page.
	 */
	if (elf->e_shoff < SMALL_PAGE_SIZE) {
		assert(!elf->is_main);
		offs = MIN(SMALL_PAGE_SIZE - elf->e_shoff, sz);
		memcpy(elf->shdr, (void *)(elf->load_addr + elf->e_shoff),
		       offs);
	}

	if (offs < sz) {
		res = sys_copy_from_ta_bin((uint8_t *)elf->shdr + offs,
					   sz - offs, elf->handle,
					   elf->e_shoff + offs);
		if (res)
			err(res, "sys_copy_from_ta_bin");
	}
}

static void close_handle(struct ta_elf *elf)
{
	TEE_Result res = sys_close_ta_bin(elf->handle);

	if (res)
		err(res, "sys_close_ta_bin");
	elf->handle = -1;
}

void ta_elf_load_main(const TEE_UUID *uuid, uint32_t *is_32bit,
		      uint64_t *entry, uint64_t *sp, uint32_t *ta_flags)
{
	struct ta_elf *elf = queue_elf(uuid);
	struct ta_head *head;
	vaddr_t va = 0;
	TEE_Result res = TEE_SUCCESS;

	assert(elf);
	elf->is_main = true;

	init_elf(elf);

	/*
	 * Legacy TAs doesn't set entry point, instead it's set in ta_head.
	 * If entry point isn't set explicitly, set to the start of the
	 * first executable section by the linker. Since ta_head also
	 * always comes first in legacy TA it means that the entry point
	 * will be set to 0x20.
	 *
	 * NB, everything before the commit a73b5878c89d ("Replace
	 * ta_head.entry with elf entry") is considered legacy TAs for
	 * ldelf.
	 */
	if (elf->e_entry == sizeof(*head))
		elf->is_legacy = true;

	map_segments(elf);
	add_dependencies(elf);
	copy_section_headers(elf);
	save_symtab(elf);
	close_handle(elf);

	head = (struct ta_head *)elf->load_addr;

	*is_32bit = elf->is_32bit;
	if (elf->is_legacy) {
		assert(head->depr_entry != UINT64_MAX);
		*entry = head->depr_entry + elf->load_addr;
	} else {
		assert(head->depr_entry == UINT64_MAX);
		*entry = elf->e_entry + elf->load_addr;
	}

	res = sys_map_zi(head->stack_size, 0, &va, 0, 0);
	if (res)
		err(res, "sys_map_zi stack");

	if (head->flags & ~TA_FLAGS_MASK)
		err(TEE_ERROR_BAD_FORMAT, "Invalid TA flags(s) %#"PRIx32,
		    head->flags & ~TA_FLAGS_MASK);

	*ta_flags = head->flags;
	*sp = va + head->stack_size;
	ta_stack = va;
	ta_stack_size = head->stack_size;
}

void ta_elf_load_dependency(struct ta_elf *elf, bool is_32bit)
{
	if (elf->is_main)
		return;

	init_elf(elf);
	if (elf->is_32bit != is_32bit)
		err(TEE_ERROR_BAD_FORMAT, "ELF %pUl is %sbit (expected %sbit)",
		    (void *)&elf->uuid, elf->is_32bit ? "32" : "64",
		    is_32bit ? "32" : "64");

	map_segments(elf);
	add_dependencies(elf);
	copy_section_headers(elf);
	save_symtab(elf);
	close_handle(elf);
}

void ta_elf_finalize_mappings(struct ta_elf *elf)
{
	TEE_Result res = TEE_SUCCESS;
	struct segment *seg = NULL;

	if (!elf->is_legacy)
		return;

	TAILQ_FOREACH(seg, &elf->segs, link) {
		vaddr_t va = elf->load_addr + seg->vaddr;
		uint32_t flags =  0;

		if (seg->flags & PF_W)
			flags |= PTA_SYSTEM_MAP_FLAG_WRITEABLE;
		if (seg->flags & PF_X)
			flags |= PTA_SYSTEM_MAP_FLAG_EXECUTABLE;

		res = sys_set_prot(va, seg->memsz, flags);
		if (res)
			err(res, "sys_set_prot");
	}
}

static void print_seg(size_t idx __maybe_unused, int elf_idx __maybe_unused,
		      vaddr_t va __maybe_unused, paddr_t pa __maybe_unused,
		      size_t sz __maybe_unused, uint32_t flags)
{
	int width __maybe_unused = 8;
	char desc[14] __maybe_unused = "";
	char flags_str[] __maybe_unused = "----";

	if (elf_idx > -1) {
		snprintf(desc, sizeof(desc), " [%d]", elf_idx);
	} else {
		if (flags & DUMP_MAP_EPHEM)
			snprintf(desc, sizeof(desc), " (param)");
		if (flags & DUMP_MAP_LDELF)
			snprintf(desc, sizeof(desc), " (ldelf)");
		if (va == ta_stack)
			snprintf(desc, sizeof(desc), " (stack)");
	}

	if (flags & DUMP_MAP_READ)
		flags_str[0] = 'r';
	if (flags & DUMP_MAP_WRITE)
		flags_str[1] = 'w';
	if (flags & DUMP_MAP_EXEC)
		flags_str[2] = 'x';
	if (flags & DUMP_MAP_SECURE)
		flags_str[3] = 's';

	EMSG_RAW("region %2zu: va 0x%0*"PRIxVA" pa 0x%0*"PRIxPA" size 0x%06zx flags %s%s",
		 idx, width, va, width, pa, sz, flags_str, desc);
}

static bool get_next_in_order(struct ta_elf_queue *elf_queue,
			      struct ta_elf **elf, struct segment **seg,
			      size_t *elf_idx)
{
	struct ta_elf *e = NULL;
	struct segment *s = NULL;
	size_t idx = 0;
	vaddr_t va = 0;
	struct ta_elf *e2 = NULL;
	size_t i2 = 0;

	assert(elf && seg && elf_idx);
	e = *elf;
	s = *seg;
	assert((e == NULL && s == NULL) || (e != NULL && s != NULL));

	if (s) {
		s = TAILQ_NEXT(s, link);
		if (s) {
			*seg = s;
			return true;
		}
	}

	if (e)
		va = e->load_addr;

	/* Find the ELF with next load address */
	e = NULL;
	TAILQ_FOREACH(e2, elf_queue, link) {
		if (e2->load_addr > va) {
			if (!e || e2->load_addr < e->load_addr) {
				e = e2;
				idx = i2;
			}
		}
		i2++;
	}
	if (!e)
		return false;

	*elf = e;
	*seg = TAILQ_FIRST(&e->segs);
	*elf_idx = idx;
	return true;
}

void ta_elf_print_mappings(struct ta_elf_queue *elf_queue, size_t num_maps,
			   struct dump_map *maps, vaddr_t mpool_base)
{
	struct segment *seg = NULL;
	struct ta_elf *elf = NULL;
	size_t elf_idx = 0;
	size_t idx = 0;
	size_t map_idx = 0;

	/*
	 * Loop over all segments and maps, printing virtual address in
	 * order. Segment has priority if the virtual address is present
	 * in both map and segment.
	 */
	get_next_in_order(elf_queue, &elf, &seg, &elf_idx);
	while (true) {
		vaddr_t va = -1;
		size_t sz = 0;
		uint32_t flags = DUMP_MAP_SECURE;
		size_t offs = 0;

		if (seg) {
			va = rounddown(seg->vaddr + elf->load_addr);
			sz = roundup(seg->vaddr + seg->memsz) -
				     rounddown(seg->vaddr);
		}

		while (map_idx < num_maps && maps[map_idx].va <= va) {
			uint32_t f = 0;

			/* If there's a match, it should be the same map */
			if (maps[map_idx].va == va) {
				/*
				 * In shared libraries the first page is
				 * mapped separately with the rest of that
				 * segment following back to back in a
				 * separate entry.
				 */
				if (map_idx + 1 < num_maps &&
				    maps[map_idx].sz == SMALL_PAGE_SIZE) {
					vaddr_t next_va = maps[map_idx].va +
							  maps[map_idx].sz;
					size_t comb_sz = maps[map_idx].sz +
							 maps[map_idx + 1].sz;

					if (next_va == maps[map_idx + 1].va &&
					    comb_sz == sz &&
					    maps[map_idx].flags ==
					    maps[map_idx + 1].flags) {
						/* Skip this and next entry */
						map_idx += 2;
						continue;
					}
				}
				assert(maps[map_idx].sz == sz);
			} else if (maps[map_idx].va < va) {
				if (maps[map_idx].va == mpool_base)
					f |= DUMP_MAP_LDELF;
				print_seg(idx, -1, maps[map_idx].va,
					  maps[map_idx].pa, maps[map_idx].sz,
					  maps[map_idx].flags | f);
				idx++;
			}
			map_idx++;
		}

		if (!seg)
			break;

		offs = rounddown(seg->offset);
		if (seg->flags & PF_R)
			flags |= DUMP_MAP_READ;
		if (seg->flags & PF_W)
			flags |= DUMP_MAP_WRITE;
		if (seg->flags & PF_X)
			flags |= DUMP_MAP_EXEC;

		print_seg(idx, elf_idx, va, offs, sz, flags);
		idx++;

		if (!get_next_in_order(elf_queue, &elf, &seg, &elf_idx))
			seg = NULL;
	}

	elf_idx = 0;
	TAILQ_FOREACH(elf, elf_queue, link) {
		EMSG_RAW(" [%zu] %pUl @ 0x%0*" PRIxVA,
			 elf_idx, (void *)&elf->uuid, 8, elf->load_addr);
		elf_idx++;
	}
}

#ifdef CFG_UNWIND
void ta_elf_stack_trace_a32(uint32_t regs[16])
{
	struct unwind_state_arm32 state = { };

	memcpy(state.registers, regs, sizeof(state.registers));
	print_stack_arm32(&state, ta_stack, ta_stack_size);
}

void ta_elf_stack_trace_a64(uint64_t fp, uint64_t sp, uint64_t pc)
{
	struct unwind_state_arm64 state = { .fp = fp, .sp = sp, .pc = pc };

	print_stack_arm64(&state, ta_stack, ta_stack_size);
}
#endif
