// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2019, Linaro Limited
 * Copyright (c) 2020, Arm Limited
 */

#include <assert.h>
#include <config.h>
#include <confine_array_index.h>
#include <ctype.h>
#include <elf32.h>
#include <elf64.h>
#include <elf_common.h>
#include <ldelf.h>
#include <link.h>
#include <stdio.h>
#include <stdlib.h>
#include <string_ext.h>
#include <string.h>
#include <tee_api_types.h>
#include <tee_internal_api_extensions.h>
#include <unw/unwind.h>
#include <user_ta_header.h>
#include <util.h>

#include "sys.h"
#include "ta_elf.h"

/*
 * Layout of a 32-bit struct dl_phdr_info for a 64-bit ldelf to access a 32-bit
 * TA
 */
struct dl_phdr_info32 {
	uint32_t dlpi_addr;
	uint32_t dlpi_name;
	uint32_t dlpi_phdr;
	uint16_t dlpi_phnum;
	uint64_t dlpi_adds;
	uint64_t dlpi_subs;
	uint32_t dlpi_tls_modid;
	uint32_t dlpi_tls_data;
};

static vaddr_t ta_stack;
static vaddr_t ta_stack_size;

struct ta_elf_queue main_elf_queue = TAILQ_HEAD_INITIALIZER(main_elf_queue);

/*
 * Main application is always ID 1, shared libraries with TLS take IDs 2 and
 * above
 */
static void assign_tls_mod_id(struct ta_elf *elf)
{
	static size_t last_tls_mod_id = 1;

	if (elf->is_main)
		assert(last_tls_mod_id == 1); /* Main always comes first */
	elf->tls_mod_id = last_tls_mod_id++;
}

static struct ta_elf *queue_elf_helper(const TEE_UUID *uuid)
{
	struct ta_elf *elf = calloc(1, sizeof(*elf));

	if (!elf)
		return NULL;

	TAILQ_INIT(&elf->segs);

	elf->uuid = *uuid;
	TAILQ_INSERT_TAIL(&main_elf_queue, elf, link);
	return elf;
}

static struct ta_elf *queue_elf(const TEE_UUID *uuid)
{
	struct ta_elf *elf = ta_elf_find_elf(uuid);

	if (elf)
		return NULL;

	elf = queue_elf_helper(uuid);
	if (!elf)
		err(TEE_ERROR_OUT_OF_MEMORY, "queue_elf_helper");

	return elf;
}

struct ta_elf *ta_elf_find_elf(const TEE_UUID *uuid)
{
	struct ta_elf *elf = NULL;

	TAILQ_FOREACH(elf, &main_elf_queue, link)
		if (!memcmp(uuid, &elf->uuid, sizeof(*uuid)))
			return elf;

	return NULL;
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

static void check_phdr_in_range(struct ta_elf *elf, unsigned int type,
				vaddr_t addr, size_t memsz)
{
	vaddr_t max_addr = 0;

	if (ADD_OVERFLOW(addr, memsz, &max_addr))
		err(TEE_ERROR_BAD_FORMAT, "Program header %#x overflow", type);

	/*
	 * elf->load_addr and elf->max_addr are both using the
	 * final virtual addresses, while this program header is
	 * relative to 0.
	 */
	if (max_addr > elf->max_addr - elf->load_addr)
		err(TEE_ERROR_BAD_FORMAT, "Program header %#x out of bounds",
		    type);
}

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

static void check_range(struct ta_elf *elf, const char *name, const void *ptr,
			size_t sz)
{
	size_t max_addr = 0;

	if ((vaddr_t)ptr < elf->load_addr)
		err(TEE_ERROR_BAD_FORMAT, "%s %p out of range", name, ptr);

	if (ADD_OVERFLOW((vaddr_t)ptr, sz, &max_addr))
		err(TEE_ERROR_BAD_FORMAT, "%s range overflow", name);

	if (max_addr > elf->max_addr)
		err(TEE_ERROR_BAD_FORMAT,
		    "%s %p..%#zx out of range", name, ptr, max_addr);
}

static void check_hashtab(struct ta_elf *elf, void *ptr, size_t num_buckets,
			  size_t num_chains)
{
	/*
	 * Starting from 2 as the first two words are mandatory and hold
	 * num_buckets and num_chains. So this function is called twice,
	 * first to see that there's indeed room for num_buckets and
	 * num_chains and then to see that all of it fits.
	 * See http://www.sco.com/developers/gabi/latest/ch5.dynamic.html#hash
	 */
	size_t num_words = 2;
	size_t sz = 0;

	if (!IS_ALIGNED_WITH_TYPE(ptr, uint32_t))
		err(TEE_ERROR_BAD_FORMAT, "Bad alignment of DT_HASH %p", ptr);

	if (ADD_OVERFLOW(num_words, num_buckets, &num_words) ||
	    ADD_OVERFLOW(num_words, num_chains, &num_words) ||
	    MUL_OVERFLOW(num_words, sizeof(uint32_t), &sz))
		err(TEE_ERROR_BAD_FORMAT, "DT_HASH overflow");

	check_range(elf, "DT_HASH", ptr, sz);
}

static void check_gnu_hashtab(struct ta_elf *elf, void *ptr)
{
	struct gnu_hashtab *h = ptr;
	size_t num_words = 4; /* nbuckets, symoffset, bloom_size, bloom_shift */
	size_t bloom_words = 0;
	size_t sz = 0;

	if (!IS_ALIGNED_WITH_TYPE(ptr, uint32_t))
		err(TEE_ERROR_BAD_FORMAT, "Bad alignment of DT_GNU_HASH %p",
		    ptr);

	if (elf->gnu_hashtab_size < sizeof(*h))
		err(TEE_ERROR_BAD_FORMAT, "DT_GNU_HASH too small");

	/* Check validity of h->nbuckets and h->bloom_size */

	if (elf->is_32bit)
		bloom_words = h->bloom_size;
	else
		bloom_words = h->bloom_size * 2;
	if (ADD_OVERFLOW(num_words, h->nbuckets, &num_words) ||
	    ADD_OVERFLOW(num_words, bloom_words, &num_words) ||
	    MUL_OVERFLOW(num_words, sizeof(uint32_t), &sz) ||
	    sz > elf->gnu_hashtab_size)
		err(TEE_ERROR_BAD_FORMAT, "DT_GNU_HASH overflow");
}

static void save_hashtab(struct ta_elf *elf)
{
	uint32_t *hashtab = NULL;
	size_t n = 0;

	if (elf->is_32bit) {
		Elf32_Shdr *shdr = elf->shdr;

		for (n = 0; n < elf->e_shnum; n++) {
			void *addr = (void *)(vaddr_t)(shdr[n].sh_addr +
						       elf->load_addr);

			if (shdr[n].sh_type == SHT_HASH) {
				elf->hashtab = addr;
			} else if (shdr[n].sh_type == SHT_GNU_HASH) {
				elf->gnu_hashtab = addr;
				elf->gnu_hashtab_size = shdr[n].sh_size;
			}
		}
	} else {
		Elf64_Shdr *shdr = elf->shdr;

		for (n = 0; n < elf->e_shnum; n++) {
			void *addr = (void *)(vaddr_t)(shdr[n].sh_addr +
						       elf->load_addr);

			if (shdr[n].sh_type == SHT_HASH) {
				elf->hashtab = addr;
			} else if (shdr[n].sh_type == SHT_GNU_HASH) {
				elf->gnu_hashtab = addr;
				elf->gnu_hashtab_size = shdr[n].sh_size;
			}
		}
	}

	if (elf->hashtab) {
		check_hashtab(elf, elf->hashtab, 0, 0);
		hashtab = elf->hashtab;
		check_hashtab(elf, elf->hashtab, hashtab[0], hashtab[1]);
	}
	if (elf->gnu_hashtab)
		check_gnu_hashtab(elf, elf->gnu_hashtab);
}

static void save_soname_from_segment(struct ta_elf *elf, unsigned int type,
				     vaddr_t addr, size_t memsz)
{
	size_t dyn_entsize = 0;
	size_t num_dyns = 0;
	size_t n = 0;
	unsigned int tag = 0;
	size_t val = 0;
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
		if (tag == DT_SONAME) {
			elf->soname = str_tab + val;
			break;
		}
	}
}

static void save_soname(struct ta_elf *elf)
{
	size_t n = 0;

	if (elf->is_32bit) {
		Elf32_Phdr *phdr = elf->phdr;

		for (n = 0; n < elf->e_phnum; n++)
			save_soname_from_segment(elf, phdr[n].p_type,
						 phdr[n].p_vaddr,
						 phdr[n].p_memsz);
	} else {
		Elf64_Phdr *phdr = elf->phdr;

		for (n = 0; n < elf->e_phnum; n++)
			save_soname_from_segment(elf, phdr[n].p_type,
						 phdr[n].p_vaddr,
						 phdr[n].p_memsz);
	}
}

static void e32_save_symtab(struct ta_elf *elf, size_t tab_idx)
{
	Elf32_Shdr *shdr = elf->shdr;
	size_t str_idx = shdr[tab_idx].sh_link;

	elf->dynsymtab = (void *)(shdr[tab_idx].sh_addr + elf->load_addr);
	if (!IS_ALIGNED_WITH_TYPE(elf->dynsymtab, Elf32_Sym))
		err(TEE_ERROR_BAD_FORMAT, "Bad alignment of dynsymtab %p",
		    elf->dynsymtab);
	check_range(elf, "Dynsymtab", elf->dynsymtab, shdr[tab_idx].sh_size);

	if (shdr[tab_idx].sh_size % sizeof(Elf32_Sym))
		err(TEE_ERROR_BAD_FORMAT,
		    "Size of dynsymtab not an even multiple of Elf32_Sym");
	elf->num_dynsyms = shdr[tab_idx].sh_size / sizeof(Elf32_Sym);

	if (str_idx >= elf->e_shnum)
		err(TEE_ERROR_BAD_FORMAT, "Dynstr section index out of range");
	elf->dynstr = (void *)(shdr[str_idx].sh_addr + elf->load_addr);
	check_range(elf, "Dynstr", elf->dynstr, shdr[str_idx].sh_size);

	elf->dynstr_size = shdr[str_idx].sh_size;
}

static void e64_save_symtab(struct ta_elf *elf, size_t tab_idx)
{
	Elf64_Shdr *shdr = elf->shdr;
	size_t str_idx = shdr[tab_idx].sh_link;

	elf->dynsymtab = (void *)(vaddr_t)(shdr[tab_idx].sh_addr +
					   elf->load_addr);

	if (!IS_ALIGNED_WITH_TYPE(elf->dynsymtab, Elf64_Sym))
		err(TEE_ERROR_BAD_FORMAT, "Bad alignment of .dynsym/DYNSYM %p",
		    elf->dynsymtab);
	check_range(elf, ".dynsym/DYNSYM", elf->dynsymtab,
		    shdr[tab_idx].sh_size);

	if (shdr[tab_idx].sh_size % sizeof(Elf64_Sym))
		err(TEE_ERROR_BAD_FORMAT,
		    "Size of .dynsym/DYNSYM not an even multiple of Elf64_Sym");
	elf->num_dynsyms = shdr[tab_idx].sh_size / sizeof(Elf64_Sym);

	if (str_idx >= elf->e_shnum)
		err(TEE_ERROR_BAD_FORMAT,
		    ".dynstr/STRTAB section index out of range");
	elf->dynstr = (void *)(vaddr_t)(shdr[str_idx].sh_addr + elf->load_addr);
	check_range(elf, ".dynstr/STRTAB", elf->dynstr, shdr[str_idx].sh_size);

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

	save_hashtab(elf);
	save_soname(elf);
}

static void init_elf(struct ta_elf *elf)
{
	TEE_Result res = TEE_SUCCESS;
	vaddr_t va = 0;
	uint32_t flags = LDELF_MAP_FLAG_SHAREABLE;
	size_t sz = 0;

	res = sys_open_ta_bin(&elf->uuid, &elf->handle);
	if (res)
		err(res, "sys_open_ta_bin(%pUl)", (void *)&elf->uuid);

	/*
	 * Map it read-only executable when we're loading a library where
	 * the ELF header is included in a load segment.
	 */
	if (!elf->is_main)
		flags |= LDELF_MAP_FLAG_EXECUTABLE;
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

	if (MUL_OVERFLOW(elf->e_phnum, elf->e_phentsize, &sz) ||
	    ADD_OVERFLOW(sz, elf->e_phoff, &sz))
		err(TEE_ERROR_BAD_FORMAT, "Program headers size overflow");

	if (sz > SMALL_PAGE_SIZE)
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

	if (memsz < filesz)
		err(TEE_ERROR_BAD_FORMAT, "Memsz smaller than filesz");

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
			} else if (phdr[n].p_type == PT_TLS) {
				assign_tls_mod_id(elf);
			}
	} else {
		Elf64_Phdr *phdr = elf->phdr;

		for (n = 0; n < elf->e_phnum; n++)
			if (phdr[n].p_type == PT_LOAD) {
				add_segment(elf, phdr[n].p_offset,
					    phdr[n].p_vaddr, phdr[n].p_filesz,
					    phdr[n].p_memsz, phdr[n].p_flags,
					    phdr[n].p_align);
			} else if (phdr[n].p_type == PT_TLS) {
				elf->tls_start = phdr[n].p_vaddr;
				elf->tls_filesz = phdr[n].p_filesz;
				elf->tls_memsz = phdr[n].p_memsz;
			} else if (IS_ENABLED(CFG_TA_BTI) &&
				   phdr[n].p_type == PT_GNU_PROPERTY) {
				elf->prop_start = phdr[n].p_vaddr;
				elf->prop_align = phdr[n].p_align;
				elf->prop_memsz = phdr[n].p_memsz;
			}
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

	assert(elf->is_legacy);
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
		res = sys_gen_random_num(&rnd32, sizeof(rnd32));
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

	assert(!elf->is_legacy);
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
				flags |= LDELF_MAP_FLAG_WRITEABLE;
			else
				flags |= LDELF_MAP_FLAG_SHAREABLE;
			if (seg->flags & PF_X)
				flags |= LDELF_MAP_FLAG_EXECUTABLE;
			if (!(seg->flags & PF_R))
				err(TEE_ERROR_NOT_SUPPORTED,
				    "Segment must be readable");
			if (flags & LDELF_MAP_FLAG_WRITEABLE) {
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
				if (filesz != memsz)
					err(TEE_ERROR_BAD_FORMAT,
					    "Filesz and memsz mismatch");
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
			elf->max_addr = roundup(va + memsz);
			elf->max_offs += filesz;
		}
	}
}

static void ta_elf_add_bti(struct ta_elf *elf)
{
	TEE_Result res = TEE_SUCCESS;
	struct segment *seg = NULL;
	uint32_t flags = LDELF_MAP_FLAG_EXECUTABLE | LDELF_MAP_FLAG_BTI;

	TAILQ_FOREACH(seg, &elf->segs, link) {
		vaddr_t va = elf->load_addr + seg->vaddr;

		if (seg->flags & PF_X) {
			res = sys_set_prot(va, seg->memsz, flags);
			if (res)
				err(res, "sys_set_prot");
		}
	}
}

static void parse_property_segment(struct ta_elf *elf)
{
	char *desc = NULL;
	size_t align = elf->prop_align;
	size_t desc_offset = 0;
	size_t prop_offset = 0;
	vaddr_t va = 0;
	Elf_Note *note = NULL;
	char *name = NULL;

	if (!IS_ENABLED(CFG_TA_BTI) || !elf->prop_start)
		return;

	check_phdr_in_range(elf, PT_GNU_PROPERTY, elf->prop_start,
			    elf->prop_memsz);

	va = elf->load_addr + elf->prop_start;
	note = (void *)va;
	name = (char *)(note + 1);

	if (elf->prop_memsz < sizeof(*note) + sizeof(ELF_NOTE_GNU))
		return;

	if (note->n_type != NT_GNU_PROPERTY_TYPE_0 ||
	    note->n_namesz != sizeof(ELF_NOTE_GNU) ||
	    memcmp(name, ELF_NOTE_GNU, sizeof(ELF_NOTE_GNU)) ||
	    !IS_POWER_OF_TWO(align))
		return;

	desc_offset = ROUNDUP(sizeof(*note) + sizeof(ELF_NOTE_GNU), align);

	if (desc_offset > elf->prop_memsz ||
	    ROUNDUP(desc_offset + note->n_descsz, align) > elf->prop_memsz)
		return;

	desc = (char *)(va + desc_offset);

	do {
		Elf_Prop *prop = (void *)(desc + prop_offset);
		size_t data_offset = prop_offset + sizeof(*prop);

		if (note->n_descsz < data_offset)
			return;

		data_offset = confine_array_index(data_offset, note->n_descsz);

		if (prop->pr_type == GNU_PROPERTY_AARCH64_FEATURE_1_AND) {
			uint32_t *pr_data = (void *)(desc + data_offset);

			if (note->n_descsz < (data_offset + sizeof(*pr_data)) &&
			    prop->pr_datasz != sizeof(*pr_data))
				return;

			if (*pr_data & GNU_PROPERTY_AARCH64_FEATURE_1_BTI) {
				DMSG("BTI Feature present in note property");
				elf->bti_enabled = true;
			}
		}

		prop_offset += ROUNDUP(sizeof(*prop) + prop->pr_datasz, align);
	} while (prop_offset < note->n_descsz);
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
	size_t str_tab_sz = 0;

	if (type != PT_DYNAMIC)
		return;

	check_phdr_in_range(elf, type, addr, memsz);

	if (elf->is_32bit)
		dyn_entsize = sizeof(Elf32_Dyn);
	else
		dyn_entsize = sizeof(Elf64_Dyn);

	assert(!(memsz % dyn_entsize));
	num_dyns = memsz / dyn_entsize;

	for (n = 0; n < num_dyns && !(str_tab && str_tab_sz); n++) {
		read_dyn(elf, addr, n, &tag, &val);
		if (tag == DT_STRTAB)
			str_tab = (char *)(val + elf->load_addr);
		else if (tag == DT_STRSZ)
			str_tab_sz = val;
	}
	check_range(elf, ".dynstr/STRTAB", str_tab, str_tab_sz);

	for (n = 0; n < num_dyns; n++) {
		read_dyn(elf, addr, n, &tag, &val);
		if (tag != DT_NEEDED)
			continue;
		if (val >= str_tab_sz)
			err(TEE_ERROR_BAD_FORMAT,
			    "Offset into .dynstr/STRTAB out of range");
		tee_uuid_from_str(&uuid, str_tab + val);
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
	size_t sz = 0;
	size_t offs = 0;

	if (MUL_OVERFLOW(elf->e_shnum, elf->e_shentsize, &sz))
		err(TEE_ERROR_BAD_FORMAT, "Section headers size overflow");

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

static void clean_elf_load_main(struct ta_elf *elf)
{
	TEE_Result res = TEE_SUCCESS;

	/*
	 * Clean up from last attempt to load
	 */
	res = sys_unmap(elf->ehdr_addr, SMALL_PAGE_SIZE);
	if (res)
		err(res, "sys_unmap");

	while (!TAILQ_EMPTY(&elf->segs)) {
		struct segment *seg = TAILQ_FIRST(&elf->segs);
		vaddr_t va = 0;
		size_t num_bytes = 0;

		va = rounddown(elf->load_addr + seg->vaddr);
		if (seg->remapped_writeable)
			num_bytes = roundup(seg->vaddr + seg->memsz) -
				    rounddown(seg->vaddr);
		else
			num_bytes = seg->memsz;

		res = sys_unmap(va, num_bytes);
		if (res)
			err(res, "sys_unmap");

		TAILQ_REMOVE(&elf->segs, seg, link);
		free(seg);
	}

	free(elf->shdr);
	memset(&elf->is_32bit, 0,
	       (vaddr_t)&elf->uuid - (vaddr_t)&elf->is_32bit);

	TAILQ_INIT(&elf->segs);
}

#ifdef ARM64
/*
 * Allocates an offset in the TA's Thread Control Block for the TLS segment of
 * the @elf module.
 */
#define TCB_HEAD_SIZE (2 * sizeof(long))
static void set_tls_offset(struct ta_elf *elf)
{
	static size_t next_offs = TCB_HEAD_SIZE;

	if (!elf->tls_start)
		return;

	/* Module has a TLS segment */
	elf->tls_tcb_offs = next_offs;
	next_offs += elf->tls_memsz;
}
#else
static void set_tls_offset(struct ta_elf *elf __unused) {}
#endif

static void load_main(struct ta_elf *elf)
{
	init_elf(elf);
	map_segments(elf);
	populate_segments(elf);
	add_dependencies(elf);
	copy_section_headers(elf);
	save_symtab(elf);
	close_handle(elf);
	set_tls_offset(elf);
	parse_property_segment(elf);
	if (elf->bti_enabled)
		ta_elf_add_bti(elf);

	elf->head = (struct ta_head *)elf->load_addr;
	if (elf->head->depr_entry != UINT64_MAX) {
		/*
		 * Legacy TAs sets their entry point in ta_head. For
		 * non-legacy TAs the entry point of the ELF is set instead
		 * and leaving the ta_head entry point set to UINT64_MAX to
		 * indicate that it's not used.
		 *
		 * NB, everything before the commit a73b5878c89d ("Replace
		 * ta_head.entry with elf entry") is considered legacy TAs
		 * for ldelf.
		 *
		 * Legacy TAs cannot be mapped with shared memory segments
		 * so restart the mapping if it turned out we're loading a
		 * legacy TA.
		 */

		DMSG("Reloading TA %pUl as legacy TA", (void *)&elf->uuid);
		clean_elf_load_main(elf);
		elf->is_legacy = true;
		init_elf(elf);
		map_segments(elf);
		populate_segments_legacy(elf);
		add_dependencies(elf);
		copy_section_headers(elf);
		save_symtab(elf);
		close_handle(elf);
		elf->head = (struct ta_head *)elf->load_addr;
		/*
		 * Check that the TA is still a legacy TA, if it isn't give
		 * up now since we're likely under attack.
		 */
		if (elf->head->depr_entry == UINT64_MAX)
			err(TEE_ERROR_GENERIC,
			    "TA %pUl was changed on disk to non-legacy",
			    (void *)&elf->uuid);
	}

}

void ta_elf_load_main(const TEE_UUID *uuid, uint32_t *is_32bit, uint64_t *sp,
		      uint32_t *ta_flags)
{
	struct ta_elf *elf = queue_elf(uuid);
	vaddr_t va = 0;
	TEE_Result res = TEE_SUCCESS;

	assert(elf);
	elf->is_main = true;

	load_main(elf);

	*is_32bit = elf->is_32bit;
	res = sys_map_zi(elf->head->stack_size, 0, &va, 0, 0);
	if (res)
		err(res, "sys_map_zi stack");

	if (elf->head->flags & ~TA_FLAGS_MASK)
		err(TEE_ERROR_BAD_FORMAT, "Invalid TA flags(s) %#"PRIx32,
		    elf->head->flags & ~TA_FLAGS_MASK);

	*ta_flags = elf->head->flags;
	*sp = va + elf->head->stack_size;
	ta_stack = va;
	ta_stack_size = elf->head->stack_size;
}

void ta_elf_finalize_load_main(uint64_t *entry)
{
	struct ta_elf *elf = TAILQ_FIRST(&main_elf_queue);
	TEE_Result res = TEE_SUCCESS;

	assert(elf->is_main);

	res = ta_elf_set_init_fini_info_compat(elf->is_32bit);
	if (res)
		err(res, "ta_elf_set_init_fini_info_compat");
	res = ta_elf_set_elf_phdr_info(elf->is_32bit);
	if (res)
		err(res, "ta_elf_set_elf_phdr_info");

	if (elf->is_legacy)
		*entry = elf->head->depr_entry;
	else
		*entry = elf->e_entry + elf->load_addr;
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
	populate_segments(elf);
	add_dependencies(elf);
	copy_section_headers(elf);
	save_symtab(elf);
	close_handle(elf);
	set_tls_offset(elf);
	parse_property_segment(elf);
	if (elf->bti_enabled)
		ta_elf_add_bti(elf);
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
			flags |= LDELF_MAP_FLAG_WRITEABLE;
		if (seg->flags & PF_X)
			flags |= LDELF_MAP_FLAG_EXECUTABLE;

		res = sys_set_prot(va, seg->memsz, flags);
		if (res)
			err(res, "sys_set_prot");
	}
}

static void __printf(3, 4) print_wrapper(void *pctx, print_func_t print_func,
					 const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	print_func(pctx, fmt, ap);
	va_end(ap);
}

static void print_seg(void *pctx, print_func_t print_func,
		      size_t idx __maybe_unused, int elf_idx __maybe_unused,
		      vaddr_t va __maybe_unused, paddr_t pa __maybe_unused,
		      size_t sz __maybe_unused, uint32_t flags)
{
	int rc __maybe_unused = 0;
	int width __maybe_unused = 8;
	char desc[14] __maybe_unused = "";
	char flags_str[] __maybe_unused = "----";

	if (elf_idx > -1) {
		rc = snprintf(desc, sizeof(desc), " [%d]", elf_idx);
		assert(rc >= 0);
	} else {
		if (flags & DUMP_MAP_EPHEM) {
			rc = snprintf(desc, sizeof(desc), " (param)");
			assert(rc >= 0);
		}
		if (flags & DUMP_MAP_LDELF) {
			rc = snprintf(desc, sizeof(desc), " (ldelf)");
			assert(rc >= 0);
		}
		if (va == ta_stack) {
			rc = snprintf(desc, sizeof(desc), " (stack)");
			assert(rc >= 0);
		}
	}

	if (flags & DUMP_MAP_READ)
		flags_str[0] = 'r';
	if (flags & DUMP_MAP_WRITE)
		flags_str[1] = 'w';
	if (flags & DUMP_MAP_EXEC)
		flags_str[2] = 'x';
	if (flags & DUMP_MAP_SECURE)
		flags_str[3] = 's';

	print_wrapper(pctx, print_func,
		      "region %2zu: va 0x%0*"PRIxVA" pa 0x%0*"PRIxPA" size 0x%06zx flags %s%s\n",
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

void ta_elf_print_mappings(void *pctx, print_func_t print_func,
			   struct ta_elf_queue *elf_queue, size_t num_maps,
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
				print_seg(pctx, print_func, idx, -1,
					  maps[map_idx].va, maps[map_idx].pa,
					  maps[map_idx].sz,
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

		print_seg(pctx, print_func, idx, elf_idx, va, offs, sz, flags);
		idx++;

		if (!get_next_in_order(elf_queue, &elf, &seg, &elf_idx))
			seg = NULL;
	}

	elf_idx = 0;
	TAILQ_FOREACH(elf, elf_queue, link) {
		print_wrapper(pctx, print_func,
			      " [%zu] %pUl @ 0x%0*"PRIxVA"\n",
			      elf_idx, (void *)&elf->uuid, 8, elf->load_addr);
		elf_idx++;
	}
}

#ifdef CFG_UNWIND
/* Called by libunw */
bool find_exidx(vaddr_t addr, vaddr_t *idx_start, vaddr_t *idx_end)
{
	struct segment *seg = NULL;
	struct ta_elf *elf = NULL;
	vaddr_t a = 0;

	TAILQ_FOREACH(elf, &main_elf_queue, link) {
		if (addr < elf->load_addr)
			continue;
		a = addr - elf->load_addr;
		TAILQ_FOREACH(seg, &elf->segs, link) {
			if (a < seg->vaddr)
				continue;
			if (a - seg->vaddr < seg->filesz) {
				*idx_start = elf->exidx_start + elf->load_addr;
				*idx_end = elf->exidx_start + elf->load_addr +
					   elf->exidx_size;
				return true;
			}
		}
	}

	return false;
}

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

TEE_Result ta_elf_add_library(const TEE_UUID *uuid)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct ta_elf *ta = TAILQ_FIRST(&main_elf_queue);
	struct ta_elf *lib = ta_elf_find_elf(uuid);
	struct ta_elf *elf = NULL;

	if (lib)
		return TEE_SUCCESS; /* Already mapped */

	lib = queue_elf_helper(uuid);
	if (!lib)
		return TEE_ERROR_OUT_OF_MEMORY;

	for (elf = lib; elf; elf = TAILQ_NEXT(elf, link))
		ta_elf_load_dependency(elf, ta->is_32bit);

	for (elf = lib; elf; elf = TAILQ_NEXT(elf, link)) {
		ta_elf_relocate(elf);
		ta_elf_finalize_mappings(elf);
	}

	for (elf = lib; elf; elf = TAILQ_NEXT(elf, link))
		DMSG("ELF (%pUl) at %#"PRIxVA,
		     (void *)&elf->uuid, elf->load_addr);

	res = ta_elf_set_init_fini_info_compat(ta->is_32bit);
	if (res)
		return res;

	return ta_elf_set_elf_phdr_info(ta->is_32bit);
}

/* Get address/size of .init_array and .fini_array from the dynamic segment */
static void get_init_fini_array(struct ta_elf *elf, unsigned int type,
				vaddr_t addr, size_t memsz, vaddr_t *init,
				size_t *init_cnt, vaddr_t *fini,
				size_t *fini_cnt)
{
	size_t addrsz = 0;
	size_t dyn_entsize = 0;
	size_t num_dyns = 0;
	size_t n = 0;
	unsigned int tag = 0;
	size_t val = 0;

	assert(type == PT_DYNAMIC);

	check_phdr_in_range(elf, type, addr, memsz);

	if (elf->is_32bit) {
		dyn_entsize = sizeof(Elf32_Dyn);
		addrsz = 4;
	} else {
		dyn_entsize = sizeof(Elf64_Dyn);
		addrsz = 8;
	}

	assert(!(memsz % dyn_entsize));
	num_dyns = memsz / dyn_entsize;

	for (n = 0; n < num_dyns; n++) {
		read_dyn(elf, addr, n, &tag, &val);
		if (tag == DT_INIT_ARRAY)
			*init = val + elf->load_addr;
		else if (tag == DT_FINI_ARRAY)
			*fini = val + elf->load_addr;
		else if (tag == DT_INIT_ARRAYSZ)
			*init_cnt = val / addrsz;
		else if (tag == DT_FINI_ARRAYSZ)
			*fini_cnt = val / addrsz;
	}
}

/* Get address/size of .init_array and .fini_array in @elf (if present) */
static void elf_get_init_fini_array(struct ta_elf *elf, vaddr_t *init,
				    size_t *init_cnt, vaddr_t *fini,
				    size_t *fini_cnt)
{
	size_t n = 0;

	if (elf->is_32bit) {
		Elf32_Phdr *phdr = elf->phdr;

		for (n = 0; n < elf->e_phnum; n++) {
			if (phdr[n].p_type == PT_DYNAMIC) {
				get_init_fini_array(elf, phdr[n].p_type,
						    phdr[n].p_vaddr,
						    phdr[n].p_memsz,
						    init, init_cnt, fini,
						    fini_cnt);
				return;
			}
		}
	} else {
		Elf64_Phdr *phdr = elf->phdr;

		for (n = 0; n < elf->e_phnum; n++) {
			if (phdr[n].p_type == PT_DYNAMIC) {
				get_init_fini_array(elf, phdr[n].p_type,
						    phdr[n].p_vaddr,
						    phdr[n].p_memsz,
						    init, init_cnt, fini,
						    fini_cnt);
				return;
			}
		}
	}
}

/*
 * Deprecated by __elf_phdr_info below. Kept for compatibility.
 *
 * Pointers to ELF initialization and finalization functions are extracted by
 * ldelf and stored on the TA heap, then exported to the TA via the global
 * symbol __init_fini_info. libutee in OP-TEE 3.9.0 uses this mechanism.
 */

struct __init_fini {
	uint32_t flags;
	uint16_t init_size;
	uint16_t fini_size;

	void (**init)(void); /* @init_size entries */
	void (**fini)(void); /* @fini_size entries */
};

#define __IFS_VALID            BIT(0)
#define __IFS_INIT_HAS_RUN     BIT(1)
#define __IFS_FINI_HAS_RUN     BIT(2)

struct __init_fini_info {
	uint32_t reserved;
	uint16_t size;
	uint16_t pad;
	struct __init_fini *ifs; /* @size entries */
};

/* 32-bit variants for a 64-bit ldelf to access a 32-bit TA */

struct __init_fini32 {
	uint32_t flags;
	uint16_t init_size;
	uint16_t fini_size;
	uint32_t init;
	uint32_t fini;
};

struct __init_fini_info32 {
	uint32_t reserved;
	uint16_t size;
	uint16_t pad;
	uint32_t ifs;
};

static TEE_Result realloc_ifs(vaddr_t va, size_t cnt, bool is_32bit)
{
	struct __init_fini_info32 *info32 = (struct __init_fini_info32 *)va;
	struct __init_fini_info *info = (struct __init_fini_info *)va;
	struct __init_fini32 *ifs32 = NULL;
	struct __init_fini *ifs = NULL;
	size_t prev_cnt = 0;
	void *ptr = NULL;

	if (is_32bit) {
		ptr = (void *)(vaddr_t)info32->ifs;
		ptr = realloc(ptr, cnt * sizeof(struct __init_fini32));
		if (!ptr)
			return TEE_ERROR_OUT_OF_MEMORY;
		ifs32 = ptr;
		prev_cnt = info32->size;
		if (cnt > prev_cnt)
			memset(ifs32 + prev_cnt, 0,
			       (cnt - prev_cnt) * sizeof(*ifs32));
		info32->ifs = (uint32_t)(vaddr_t)ifs32;
		info32->size = cnt;
	} else {
		ptr = realloc(info->ifs, cnt * sizeof(struct __init_fini));
		if (!ptr)
			return TEE_ERROR_OUT_OF_MEMORY;
		ifs = ptr;
		prev_cnt = info->size;
		if (cnt > prev_cnt)
			memset(ifs + prev_cnt, 0,
			       (cnt - prev_cnt) * sizeof(*ifs));
		info->ifs = ifs;
		info->size = cnt;
	}

	return TEE_SUCCESS;
}

static void fill_ifs(vaddr_t va, size_t idx, struct ta_elf *elf, bool is_32bit)
{
	struct __init_fini_info32 *info32 = (struct __init_fini_info32 *)va;
	struct __init_fini_info *info = (struct __init_fini_info *)va;
	struct __init_fini32 *ifs32 = NULL;
	struct __init_fini *ifs = NULL;
	size_t init_cnt = 0;
	size_t fini_cnt = 0;
	vaddr_t init = 0;
	vaddr_t fini = 0;

	if (is_32bit) {
		assert(idx < info32->size);
		ifs32 = &((struct __init_fini32 *)(vaddr_t)info32->ifs)[idx];

		if (ifs32->flags & __IFS_VALID)
			return;

		elf_get_init_fini_array(elf, &init, &init_cnt, &fini,
					&fini_cnt);

		ifs32->init = (uint32_t)init;
		ifs32->init_size = init_cnt;

		ifs32->fini = (uint32_t)fini;
		ifs32->fini_size = fini_cnt;

		ifs32->flags |= __IFS_VALID;
	} else {
		assert(idx < info->size);
		ifs = &info->ifs[idx];

		if (ifs->flags & __IFS_VALID)
			return;

		elf_get_init_fini_array(elf, &init, &init_cnt, &fini,
					&fini_cnt);

		ifs->init = (void (**)(void))init;
		ifs->init_size = init_cnt;

		ifs->fini = (void (**)(void))fini;
		ifs->fini_size = fini_cnt;

		ifs->flags |= __IFS_VALID;
	}
}

/*
 * Set or update __init_fini_info in the TA with information from the ELF
 * queue
 */
TEE_Result ta_elf_set_init_fini_info_compat(bool is_32bit)
{
	struct __init_fini_info *info = NULL;
	TEE_Result res = TEE_SUCCESS;
	struct ta_elf *elf = NULL;
	vaddr_t info_va = 0;
	size_t cnt = 0;

	res = ta_elf_resolve_sym("__init_fini_info", &info_va, NULL, NULL);
	if (res) {
		if (res == TEE_ERROR_ITEM_NOT_FOUND) {
			/*
			 * Not an error, only TAs linked against libutee from
			 * OP-TEE 3.9.0 have this symbol.
			 */
			return TEE_SUCCESS;
		}
		return res;
	}
	assert(info_va);

	info = (struct __init_fini_info *)info_va;
	if (info->reserved)
		return TEE_ERROR_NOT_SUPPORTED;

	TAILQ_FOREACH(elf, &main_elf_queue, link)
		cnt++;

	/* Queue has at least one file (main) */
	assert(cnt);

	res = realloc_ifs(info_va, cnt, is_32bit);
	if (res)
		goto err;

	cnt = 0;
	TAILQ_FOREACH(elf, &main_elf_queue, link) {
		fill_ifs(info_va, cnt, elf, is_32bit);
		cnt++;
	}

	return TEE_SUCCESS;
err:
	free(info);
	return res;
}

static TEE_Result realloc_elf_phdr_info(vaddr_t va, size_t cnt, bool is_32bit)
{
	struct __elf_phdr_info32 *info32 = (struct __elf_phdr_info32 *)va;
	struct __elf_phdr_info *info = (struct __elf_phdr_info *)va;
	struct dl_phdr_info32 *dlpi32 = NULL;
	struct dl_phdr_info *dlpi = NULL;
	size_t prev_cnt = 0;
	void *ptr = NULL;

	if (is_32bit) {
		ptr = (void *)(vaddr_t)info32->dlpi;
		ptr = realloc(ptr, cnt * sizeof(*dlpi32));
		if (!ptr)
			return TEE_ERROR_OUT_OF_MEMORY;
		dlpi32 = ptr;
		prev_cnt = info32->count;
		if (cnt > prev_cnt)
			memset(dlpi32 + prev_cnt, 0,
			       (cnt - prev_cnt) * sizeof(*dlpi32));
		info32->dlpi = (uint32_t)(vaddr_t)dlpi32;
		info32->count = cnt;
	} else {
		ptr = realloc(info->dlpi, cnt * sizeof(*dlpi));
		if (!ptr)
			return TEE_ERROR_OUT_OF_MEMORY;
		dlpi = ptr;
		prev_cnt = info->count;
		if (cnt > prev_cnt)
			memset(dlpi + prev_cnt, 0,
			       (cnt - prev_cnt) * sizeof(*dlpi));
		info->dlpi = dlpi;
		info->count = cnt;
	}

	return TEE_SUCCESS;
}

static void fill_elf_phdr_info(vaddr_t va, size_t idx, struct ta_elf *elf,
			       bool is_32bit)
{
	struct __elf_phdr_info32 *info32 = (struct __elf_phdr_info32 *)va;
	struct __elf_phdr_info *info = (struct __elf_phdr_info *)va;
	struct dl_phdr_info32 *dlpi32 = NULL;
	struct dl_phdr_info *dlpi = NULL;

	if (is_32bit) {
		assert(idx < info32->count);
		dlpi32 = (struct dl_phdr_info32 *)(vaddr_t)info32->dlpi + idx;

		dlpi32->dlpi_addr = elf->load_addr;
		if (elf->soname)
			dlpi32->dlpi_name = (vaddr_t)elf->soname;
		else
			dlpi32->dlpi_name = (vaddr_t)&info32->zero;
		dlpi32->dlpi_phdr = (vaddr_t)elf->phdr;
		dlpi32->dlpi_phnum = elf->e_phnum;
		dlpi32->dlpi_adds = 1; /* No unloading on dlclose() currently */
		dlpi32->dlpi_subs = 0; /* No unloading on dlclose() currently */
		dlpi32->dlpi_tls_modid = elf->tls_mod_id;
		dlpi32->dlpi_tls_data = elf->tls_start;
	} else {
		assert(idx < info->count);
		dlpi = info->dlpi + idx;

		dlpi->dlpi_addr = elf->load_addr;
		if (elf->soname)
			dlpi->dlpi_name = elf->soname;
		else
			dlpi->dlpi_name = &info32->zero;
		dlpi->dlpi_phdr = elf->phdr;
		dlpi->dlpi_phnum = elf->e_phnum;
		dlpi->dlpi_adds = 1; /* No unloading on dlclose() currently */
		dlpi->dlpi_subs = 0; /* No unloading on dlclose() currently */
		dlpi->dlpi_tls_modid = elf->tls_mod_id;
		dlpi->dlpi_tls_data = (void *)elf->tls_start;
	}
}

/* Set or update __elf_hdr_info in the TA with information from the ELF queue */
TEE_Result ta_elf_set_elf_phdr_info(bool is_32bit)
{
	struct __elf_phdr_info *info = NULL;
	TEE_Result res = TEE_SUCCESS;
	struct ta_elf *elf = NULL;
	vaddr_t info_va = 0;
	size_t cnt = 0;

	res = ta_elf_resolve_sym("__elf_phdr_info", &info_va, NULL, NULL);
	if (res) {
		if (res == TEE_ERROR_ITEM_NOT_FOUND) {
			/* Older TA */
			return TEE_SUCCESS;
		}
		return res;
	}
	assert(info_va);

	info = (struct __elf_phdr_info *)info_va;
	if (info->reserved)
		return TEE_ERROR_NOT_SUPPORTED;

	TAILQ_FOREACH(elf, &main_elf_queue, link)
		cnt++;

	res = realloc_elf_phdr_info(info_va, cnt, is_32bit);
	if (res)
		return res;

	cnt = 0;
	TAILQ_FOREACH(elf, &main_elf_queue, link) {
		fill_elf_phdr_info(info_va, cnt, elf, is_32bit);
		cnt++;
	}

	return TEE_SUCCESS;
}
