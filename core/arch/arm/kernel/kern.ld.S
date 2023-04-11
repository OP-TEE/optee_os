/* SPDX-License-Identifier: (BSD-2-Clause AND MIT) */
/*
 * Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Copyright (c) 2008-2010 Travis Geiselbrecht
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files
 * (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge,
 * publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <mm/core_mmu.h>
#include <platform_config.h>
#include <util.h>

/*
 * Note:
 * Clang 11 (ld.lld) generates non-relocatable reference when using ROUNDDOWN()
 * from <util.h>, which does not work with ASLR.
 */
#define LD_ROUNDDOWN(x, y) ((x) - ((x) % (y)))

OUTPUT_FORMAT(CFG_KERN_LINKER_FORMAT)
OUTPUT_ARCH(CFG_KERN_LINKER_ARCH)

ENTRY(_start)
SECTIONS
{
	. = TEE_LOAD_ADDR;
	ASSERT(!(TEE_LOAD_ADDR & (SMALL_PAGE_SIZE - 1)),
	       "text start should be page aligned")
	__text_start = .;

	/*
	 * Memory between TEE_LOAD_ADDR and page aligned rounded down
	 * value will be mapped with unpaged "text" section attributes:
	 * likely to be read-only/executable.
	 */
	__flatmap_unpg_rx_start = LD_ROUNDDOWN(__text_start, SMALL_PAGE_SIZE);

	.text : {
		KEEP(*(.text._start))
		__identity_map_init_start = .;
		__text_data_start = .;
		*(.identity_map.data)
		__text_data_end = .;
		*(.identity_map .identity_map.* \
			/*
			 * The one below is needed because it's a weak
			 * symbol that may be overridden by platform
			 * specific code.
			 */
		  .text.get_core_pos_mpidr)
		__identity_map_init_end = .;
		KEEP(*(.text.init .text.plat_cpu_reset_early \
		       .text.reset .text.reset_primary .text.unhandled_cpu \
		       .text.__assert_flat_mapped_range))

#ifdef CFG_WITH_PAGER
		*(.text)
/* Include list of sections needed for paging */
#include <text_unpaged.ld.S>
#else
		*(.text .text.*)
#endif
		*(.sram.text.glue_7* .gnu.linkonce.t.*)
		. = ALIGN(8);
	}
	__text_end = .;

#ifdef CFG_CORE_RODATA_NOEXEC
	. = ALIGN(SMALL_PAGE_SIZE);
#endif
	__flatmap_unpg_rx_size = . - __flatmap_unpg_rx_start;
	__flatmap_unpg_ro_start = .;

	.rodata : ALIGN(8) {
		__rodata_start = .;
		*(.gnu.linkonce.r.*)
#ifdef CFG_WITH_PAGER
		*(.rodata .rodata.__unpaged .rodata.__unpaged.*)
#include <rodata_unpaged.ld.S>
#else
		*(.rodata .rodata.*)
#ifndef CFG_CORE_ASLR
		. = ALIGN(8);
		KEEP(*(SORT(.scattered_array*)));
#endif
#endif
		. = ALIGN(8);
		__rodata_end = .;
	}

#if defined(CFG_CORE_ASLR)
	.data.rel.ro : {
#if !defined(CFG_WITH_PAGER)
		. = ALIGN(8);
		KEEP(*(SORT(.scattered_array*)));
#endif
		*(.data.rel.ro.__unpaged .data.rel.ro.__unpaged.*)
	}
#endif

	.got : { *(.got.plt) *(.got) }
	.note.gnu.property : { *(.note.gnu.property) }
	.plt : { *(.plt) }

	.ctors : ALIGN(8) {
		__ctor_list = .;
		KEEP(*(.ctors .ctors.* .init_array .init_array.*))
		__ctor_end = .;
	}
	.dtors : ALIGN(8) {
		__dtor_list = .;
		KEEP(*(.dtors .dtors.* .fini_array .fini_array.*))
		__dtor_end = .;
	}

	/* .ARM.exidx is sorted, so has to go in its own output section.  */
	.ARM.exidx : {
		__exidx_start = .;
		*(.ARM.exidx* .gnu.linkonce.armexidx.*)
		__exidx_end = .;
	}

	.ARM.extab : {
		__extab_start = .;
		*(.ARM.extab*)
		__extab_end = .;
	}

	/* Start page aligned read-write memory */
#ifdef CFG_CORE_RWDATA_NOEXEC
	. = ALIGN(SMALL_PAGE_SIZE);
#endif
	__flatmap_unpg_ro_size = . - __flatmap_unpg_ro_start;

#ifdef CFG_NS_VIRTUALIZATION
	__flatmap_nex_rw_start = . ;
	.nex_data : ALIGN(8) {
		*(.nex_data .nex_data.*)
	}

	.nex_bss : ALIGN(8) {
		__nex_bss_start = .;
		*(.nex_bss .nex_bss.*)
		__nex_bss_end = .;
	}

	/*
	 * We want to keep all nexus memory in one place, because
	 * it should be always mapped and it is easier to map one
	 * memory region than two.
	 * Next section are NOLOAD ones, but they are followed
	 * by sections with data. Thus, this NOLOAD section will
	 * be included in the resulting binary, filled with zeroes
	 */
	.nex_stack (NOLOAD) : {
		__nozi_stack_start = .;
		KEEP(*(.nozi_stack.stack_tmp .nozi_stack.stack_abt))
		. = ALIGN(8);
		__nozi_stack_end = .;
	}

	.nex_heap (NOLOAD) : {
		__nex_heap_start = .;
		. += CFG_CORE_NEX_HEAP_SIZE;
		. = ALIGN(16 * 1024);
		__nex_heap_end = .;
	}
	.nex_nozi (NOLOAD) : {
		ASSERT(!(ABSOLUTE(.) & (16 * 1024 - 1)), "align nozi to 16kB");
		KEEP(*(.nozi.mmu.base_table .nozi.mmu.l2))
	}

	. = ALIGN(SMALL_PAGE_SIZE);

	__flatmap_nex_rw_size = . - __flatmap_nex_rw_start;
	__flatmap_nex_rw_end = .;
#endif

	__flatmap_unpg_rw_start = .;

	.data : ALIGN(8) {
		/* writable data  */
		__data_start_rom = .;
		/* in one segment binaries, the rom data address is on top
		   of the ram data address */
		__data_start = .;
		*(.data .data.* .gnu.linkonce.d.*)
		. = ALIGN(8);
	}

	/* unintialized data */
	.bss : {
		__data_end = .;
		__bss_start = .;
		*(.bss .bss.*)
		*(.gnu.linkonce.b.*)
		*(COMMON)
		. = ALIGN(8);
		__bss_end = .;
	}

	.heap1 (NOLOAD) : {
		/*
		 * We're keeping track of the padding added before the
		 * .nozi section so we can do something useful with
		 * this otherwise wasted memory.
		 */
		__heap1_start = .;
#ifndef CFG_WITH_PAGER
		. += CFG_CORE_HEAP_SIZE;
#endif
#ifdef CFG_WITH_LPAE
		. = ALIGN(4 * 1024);
#else
		. = ALIGN(16 * 1024);
#endif
		__heap1_end = .;
	}
	/*
	 * Uninitialized data that shouldn't be zero initialized at
	 * runtime.
	 *
	 * L1 mmu table requires 16 KiB alignment
	 */
	.nozi (NOLOAD) : {
		__nozi_start = .;
		KEEP(*(.nozi .nozi.*))
		. = ALIGN(16);
		__nozi_end = .;
		/*
		 * If virtualization is enabled, abt and tmp stacks will placed
		 * at above .nex_stack section and thread stacks will go there
		 */
		__nozi_stack_start = .;
		KEEP(*(.nozi_stack .nozi_stack.*))
		. = ALIGN(8);
		__nozi_stack_end = .;
	}

#ifdef CFG_WITH_PAGER
	.heap2 (NOLOAD) : {
		__heap2_start = .;
		/*
		 * Reserve additional memory for heap, the total should be
		 * at least CFG_CORE_HEAP_SIZE, but count what has already
		 * been reserved in .heap1
		 */
		. += CFG_CORE_HEAP_SIZE - (__heap1_end - __heap1_start);
		. = ALIGN(SMALL_PAGE_SIZE);
		__heap2_end = .;
	}

	/* Start page aligned read-only memory */
	__flatmap_unpg_rw_size = . - __flatmap_unpg_rw_start;

	__init_start = .;
	__flatmap_init_rx_start = .;

	ASSERT(!(__flatmap_init_rx_start & (SMALL_PAGE_SIZE - 1)),
		"read-write memory is not paged aligned")

	.text_init : {
		__text_init_start = .;
/*
 * Include list of sections needed for boot initialization, this list
 * overlaps with unpaged.ld.S but since unpaged.ld.S is first all those
 * sections will go into the unpaged area.
 */
#include <text_init.ld.S>
		KEEP(*(.text.startup.*));
		/* Make sure constructor functions are available during init */
		KEEP(*(.text._GLOBAL__sub_*));
		. = ALIGN(8);
		__text_init_end = .;
	}

#ifdef CFG_CORE_RODATA_NOEXEC
	. = ALIGN(SMALL_PAGE_SIZE);
#endif
	__flatmap_init_rx_size = . - __flatmap_init_rx_start;
	__flatmap_init_ro_start = .;

	.rodata_init : {
		__rodata_init_start = .;
#include <rodata_init.ld.S>
#ifndef CFG_CORE_ASLR
		. = ALIGN(8);
		KEEP(*(SORT(.scattered_array*)));
#endif
		__rodata_init_end = .;
	}
#ifdef CFG_CORE_ASLR
	.data.rel.ro_init : ALIGN(8) {
		KEEP(*(SORT(.scattered_array*)));
	}
#endif
	. = ALIGN(8);
	__ro_and_relro_data_init_end = .;

	__init_end = ALIGN(__ro_and_relro_data_init_end, SMALL_PAGE_SIZE);
	__get_tee_init_end = __init_end;
	__init_size = __init_end - __init_start;

	/* vcore flat map stops here. No need to page align, rodata follows. */
	__flatmap_init_ro_size = __init_end - __flatmap_init_ro_start;

	.rodata_pageable : ALIGN(8) {
		__rodata_pageable_start = .;
		*(.rodata*)
		__rodata_pageable_end = .;
	}

#ifdef CFG_CORE_RODATA_NOEXEC
	. = ALIGN(SMALL_PAGE_SIZE);
#endif

	.text_pageable : ALIGN(8) {
		__text_pageable_start = .;
		*(.text*)
		. = ALIGN(SMALL_PAGE_SIZE);
		__text_pageable_end = .;
	}

	__pageable_part_end = .;
	__pageable_part_start = __init_end;
	__pageable_start = __init_start;
	__pageable_end = __pageable_part_end;

	ASSERT(TEE_LOAD_ADDR >= TEE_RAM_START,
		"Load address before start of physical memory")
	ASSERT(TEE_LOAD_ADDR < (TEE_RAM_START + TEE_RAM_PH_SIZE),
		"Load address after end of physical memory")
	ASSERT((TEE_RAM_START + TEE_RAM_PH_SIZE - __init_end) >
		SMALL_PAGE_SIZE, "Too few free pages to initialize paging")


#endif /*CFG_WITH_PAGER*/

#ifdef CFG_CORE_SANITIZE_KADDRESS
	. = TEE_RAM_START + (TEE_RAM_VA_SIZE * 8) / 9 - 8;
	. = ALIGN(8);
	.asan_shadow : {
		__asan_shadow_start = .;
		. += TEE_RAM_VA_SIZE / 9;
		__asan_shadow_end = .;
		__asan_shadow_size = __asan_shadow_end - __asan_shadow_start;
	}
#endif /*CFG_CORE_SANITIZE_KADDRESS*/

	__end = .;

#ifndef CFG_WITH_PAGER
	__init_size = __data_end - TEE_LOAD_ADDR;
#endif
	/*
	 * Guard against moving the location counter backwards in the assignment
	 * below.
	 */
	ASSERT(. <= (TEE_RAM_START + TEE_RAM_VA_SIZE),
		"TEE_RAM_VA_SIZE is too small")
	. = TEE_RAM_START + TEE_RAM_VA_SIZE;

	_end_of_ram = .;

#ifndef CFG_WITH_PAGER
	__flatmap_unpg_rw_size = _end_of_ram - __flatmap_unpg_rw_start;
	__get_tee_init_end = .;
#endif

	/*
	 * These regions will not become a normal part of the dumped
	 * binary, instead some are interpreted by the dump script and
	 * converted into suitable format for OP-TEE itself to use.
	 */
	.dynamic : { *(.dynamic) }
	.hash : { *(.hash) }
	.dynsym : { *(.dynsym) }
	.dynstr : { *(.dynstr) }

	.rel : {
		*(.rel.*)
	}
	.rela : {
		*(.rela.*)
	}
#if !defined(CFG_CORE_ASLR) && !defined(CFG_CORE_PHYS_RELOCATABLE)
	ASSERT(SIZEOF(.rel) == 0, "Relocation entries not expected")
	ASSERT(SIZEOF(.rela) == 0, "Relocation entries not expected")
#endif

	/DISCARD/ : {
		/* Strip unnecessary stuff */
		*(.comment .note .eh_frame .interp)
		/* Strip meta variables */
		*(__keep_meta_vars*)
	}

}

/* Unpaged read-only memories */
__vcore_unpg_rx_start = __flatmap_unpg_rx_start;
__vcore_unpg_ro_start = __flatmap_unpg_ro_start;
#ifdef CFG_CORE_RODATA_NOEXEC
__vcore_unpg_rx_size = __flatmap_unpg_rx_size;
__vcore_unpg_ro_size = __flatmap_unpg_ro_size;
#else
__vcore_unpg_rx_size = __flatmap_unpg_rx_size + __flatmap_unpg_ro_size;
__vcore_unpg_ro_size = 0;
#endif
__vcore_unpg_rx_end = __vcore_unpg_rx_start + __vcore_unpg_rx_size;
__vcore_unpg_ro_end = __vcore_unpg_ro_start + __vcore_unpg_ro_size;

/* Unpaged read-write memory */
__vcore_unpg_rw_start = __flatmap_unpg_rw_start;
__vcore_unpg_rw_size = __flatmap_unpg_rw_size;
__vcore_unpg_rw_end = __vcore_unpg_rw_start + __vcore_unpg_rw_size;

#ifdef CFG_NS_VIRTUALIZATION
/* Nexus read-write memory */
__vcore_nex_rw_start = __flatmap_nex_rw_start;
__vcore_nex_rw_size = __flatmap_nex_rw_size;
__vcore_nex_rw_end = __vcore_nex_rw_start + __vcore_nex_rw_size;
#endif

#ifdef CFG_WITH_PAGER
/*
 * Core init mapping shall cover up to end of the physical RAM.
 * This is required since the hash table is appended to the
 * binary data after the firmware build sequence.
 */
#define __FLATMAP_PAGER_TRAILING_SPACE	\
	(TEE_RAM_START + TEE_RAM_PH_SIZE - \
		(__flatmap_init_ro_start + __flatmap_init_ro_size))

/* Paged/init read-only memories */
__vcore_init_rx_start = __flatmap_init_rx_start;
__vcore_init_ro_start = __flatmap_init_ro_start;
#ifdef CFG_CORE_RODATA_NOEXEC
__vcore_init_rx_size = __flatmap_init_rx_size;
__vcore_init_ro_size = __flatmap_init_ro_size + __FLATMAP_PAGER_TRAILING_SPACE;
#else
__vcore_init_rx_size = __flatmap_init_rx_size + __flatmap_init_ro_size +
		       __FLATMAP_PAGER_TRAILING_SPACE;
__vcore_init_ro_size = 0;
#endif /* CFG_CORE_RODATA_NOEXEC */
__vcore_init_rx_end = __vcore_init_rx_start + __vcore_init_rx_size;
__vcore_init_ro_end = __vcore_init_ro_start + __vcore_init_ro_size;
#endif /* CFG_WITH_PAGER */

#ifdef CFG_CORE_SANITIZE_KADDRESS
__asan_map_start = (__asan_shadow_start / SMALL_PAGE_SIZE) *
		   SMALL_PAGE_SIZE;
__asan_map_end = ((__asan_shadow_end - 1) / SMALL_PAGE_SIZE) *
		 SMALL_PAGE_SIZE + SMALL_PAGE_SIZE;
__asan_map_size = __asan_map_end - __asan_map_start;
#endif /*CFG_CORE_SANITIZE_KADDRESS*/
