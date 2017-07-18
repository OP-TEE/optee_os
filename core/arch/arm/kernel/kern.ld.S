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

#include <platform_config.h>

#ifndef SMALL_PAGE_SIZE
#define SMALL_PAGE_SIZE		4096
#endif
#ifndef ROUNDUP
#define ROUNDUP(x, y)		((((x) + (y) - 1) / (y)) * (y))
#define ROUNDDOWN(x, y)		(((x) / (y)) * (y))
#endif

OUTPUT_FORMAT(CFG_KERN_LINKER_FORMAT)
OUTPUT_ARCH(CFG_KERN_LINKER_ARCH)

ENTRY(_start)
SECTIONS
{
	. = CFG_TEE_LOAD_ADDR;

	__text_start = .;

	/*
	 * Memory between CFG_TEE_LOAD_ADDR and page aligned rounded down
	 * value will be mapped with unpaged "text" section attributes:
	 * likely to be read-only/executable.
	 */
	__flatmap_unpg_rx_start = ROUNDDOWN(__text_start, SMALL_PAGE_SIZE);

	.text : {
		KEEP(*(.text.boot.vectab1))
		KEEP(*(.text.boot.vectab2))
		KEEP(*(.text.boot))

		. = ALIGN(8);
		__initcall_start = .;
		KEEP(*(.initcall1))
		KEEP(*(.initcall2))
		KEEP(*(.initcall3))
		KEEP(*(.initcall4))
		__initcall_end = .;

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
		*(.rodata .rodata.__unpaged)
#include <rodata_unpaged.ld.S>
#else
#ifdef CFG_DT
		__rodata_dtdrv_start = .;
		KEEP(*(.rodata.dtdrv))
		__rodata_dtdrv_end = .;
#endif
		*(.rodata .rodata.*)

		/*
		 * 8 to avoid unwanted padding between __start_ta_head_section
		 * and the first structure in ta_head_section, in 64-bit
		 * builds
		 */
		. = ALIGN(8);
		__start_ta_head_section = . ;
		KEEP(*(ta_head_section))
		__stop_ta_head_section = . ;
		. = ALIGN(8);
		__start_phys_mem_map_section = . ;
		KEEP(*(phys_mem_map_section))
		__end_phys_mem_map_section = . ;
		. = ALIGN(8);
		__start_phys_sdp_mem_section = . ;
		KEEP(*(phys_sdp_mem_section))
		__end_phys_sdp_mem_section = . ;
		. = ALIGN(8);
		__start_phys_nsec_ddr_section = . ;
		KEEP(*(phys_nsec_ddr_section))
		__end_phys_nsec_ddr_section = . ;
#endif
		. = ALIGN(8);
		__rodata_end = .;
	}

	.interp : { *(.interp) }
	.hash : { *(.hash) }
	.dynsym : { *(.dynsym) }
	.dynstr : { *(.dynstr) }
	.rel.text : { *(.rel.text) *(.rel.gnu.linkonce.t*) }
	.rela.text : { *(.rela.text) *(.rela.gnu.linkonce.t*) }
	.rel.data : { *(.rel.data) *(.rel.gnu.linkonce.d*) }
	.rela.data : { *(.rela.data) *(.rela.gnu.linkonce.d*) }
	.rel.rodata : { *(.rel.rodata) *(.rel.gnu.linkonce.r*) }
	.rela.rodata : { *(.rela.rodata) *(.rela.gnu.linkonce.r*) }
	.rel.got : { *(.rel.got) }
	.rela.got : { *(.rela.got) }
	.rel.ctors : { *(.rel.ctors) }
	.rela.ctors : { *(.rela.ctors) }
	.rel.dtors : { *(.rel.dtors) }
	.rela.dtors : { *(.rela.dtors) }
	.rel.init : { *(.rel.init) }
	.rela.init : { *(.rela.init) }
	.rel.fini : { *(.rel.fini) }
	.rela.fini : { *(.rela.fini) }
	.rel.bss : { *(.rel.bss) }
	.rela.bss : { *(.rela.bss) }
	.rel.plt : { *(.rel.plt) }
	.rela.plt : { *(.rela.plt) }
	.init : { *(.init) } =0x9090
	.plt : { *(.plt) }

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
	.got : { *(.got.plt) *(.got) }
	.dynamic : { *(.dynamic) }

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
		. = ALIGN(16 * 1024);
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
		ASSERT(!(__nozi_start & (16 * 1024 - 1)), "align nozi to 16kB");

		KEEP(*(.nozi .nozi.*))
		. = ALIGN(16);
		__nozi_end = .;
		__nozi_stack_start = .;
		KEEP(*(.nozi_stack))
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
/*
 * Include list of sections needed for boot initialization, this list
 * overlaps with unpaged.ld.S but since unpaged.ld.S is first all those
 * sections will go into the unpaged area.
 */
#include <text_init.ld.S>
		. = ALIGN(8);
	}

#ifdef CFG_CORE_RODATA_NOEXEC
	. = ALIGN(SMALL_PAGE_SIZE);
#endif
	__flatmap_init_rx_size = . - __flatmap_init_rx_start;
	__flatmap_init_ro_start = .;

	.rodata_init : {
#include <rodata_init.ld.S>
		. = ALIGN(8);
		__start_phys_mem_map_section = . ;
		KEEP(*(phys_mem_map_section))
		__end_phys_mem_map_section = . ;
		. = ALIGN(8);
		__start_phys_sdp_mem_section = . ;
		KEEP(*(phys_sdp_mem_section))
		__end_phys_sdp_mem_section = . ;
		. = ALIGN(8);
		__start_phys_nsec_ddr_section = . ;
		KEEP(*(phys_nsec_ddr_section))
		__end_phys_nsec_ddr_section = . ;
		. = ALIGN(8);
		__rodata_init_end = .;
	}
	__rodata_init_end = .;

	__init_end = ROUNDUP(__rodata_init_end, SMALL_PAGE_SIZE);
	__init_size = __init_end - __init_start;

	/* vcore flat map stops here. No need to page align, rodata follows. */
	__flatmap_init_ro_size = __init_end - __flatmap_init_ro_start;

	.rodata_pageable : ALIGN(8) {
#ifdef CFG_DT
		__rodata_dtdrv_start = .;
		KEEP(*(.rodata.dtdrv))
		__rodata_dtdrv_end = .;
#endif
		*(.rodata*)
		/*
		 * 8 to avoid unwanted padding between __start_ta_head_section
		 * and the first structure in ta_head_section, in 64-bit
		 * builds
		 */
		. = ALIGN(8);
		__start_ta_head_section = . ;
		KEEP(*(ta_head_section))
		__stop_ta_head_section = . ;
	}

#ifdef CFG_CORE_RODATA_NOEXEC
	. = ALIGN(SMALL_PAGE_SIZE);
#endif

	.text_pageable : ALIGN(8) {
		*(.text*)
		. = ALIGN(SMALL_PAGE_SIZE);
	}

	__pageable_part_end = .;
	__pageable_part_start = __init_end;
	__pageable_start = __init_start;
	__pageable_end = __pageable_part_end;

	/*
	 * Assign a safe spot to store the hashes of the pages before
	 * heap is initialized.
	 */
	__tmp_hashes_start = __init_end;
	__tmp_hashes_size = ((__pageable_end - __pageable_start) /
				SMALL_PAGE_SIZE) * 32;
	__tmp_hashes_end = __tmp_hashes_start + __tmp_hashes_size;

	__init_mem_usage = __tmp_hashes_end - CFG_TEE_LOAD_ADDR;

	ASSERT(CFG_TEE_LOAD_ADDR >= CFG_TEE_RAM_START,
		"Load address before start of physical memory")
	ASSERT(CFG_TEE_LOAD_ADDR < (CFG_TEE_RAM_START + CFG_TEE_RAM_PH_SIZE),
		"Load address after end of physical memory")
	ASSERT(__tmp_hashes_end < (CFG_TEE_RAM_START + CFG_TEE_RAM_PH_SIZE),
		"OP-TEE can't fit init part into available physical memory")
	ASSERT((CFG_TEE_RAM_START + CFG_TEE_RAM_PH_SIZE - __init_end) >
		SMALL_PAGE_SIZE, "Too few free pages to initialize paging")


#endif /*CFG_WITH_PAGER*/

#ifdef CFG_CORE_SANITIZE_KADDRESS
	. = CFG_TEE_RAM_START + (CFG_TEE_RAM_VA_SIZE * 8) / 9 - 8;
	. = ALIGN(8);
	.asan_shadow : {
		__asan_shadow_start = .;
		. += CFG_TEE_RAM_VA_SIZE / 9;
		__asan_shadow_end = .;
	}
#endif /*CFG_CORE_SANITIZE_KADDRESS*/

	__end = .;

#ifndef CFG_WITH_PAGER
	__init_size = __data_end - CFG_TEE_LOAD_ADDR;
	__init_mem_usage = __end - CFG_TEE_LOAD_ADDR;
#endif
	/*
	 * Guard against moving the location counter backwards in the assignment
	 * below.
	 */
	ASSERT(. <= (CFG_TEE_RAM_START + CFG_TEE_RAM_VA_SIZE),
		"CFG_TEE_RAM_VA_SIZE is too small")
	. = CFG_TEE_RAM_START + CFG_TEE_RAM_VA_SIZE;

	_end_of_ram = .;

#ifndef CFG_WITH_PAGER
	__flatmap_unpg_rw_size = _end_of_ram - __flatmap_unpg_rw_start;
#endif

	/DISCARD/ : {
		/* Strip unnecessary stuff */
		*(.comment .note .eh_frame)
		/* Strip meta variables */
		*(__keep_meta_vars*)
	}

}

/* Unpaged read-only memories */
PROVIDE(__vcore_unpg_rx_start = __flatmap_unpg_rx_start);
PROVIDE(__vcore_unpg_ro_start = __flatmap_unpg_ro_start);
#ifdef CFG_CORE_RODATA_NOEXEC
PROVIDE(__vcore_unpg_rx_size = __flatmap_unpg_rx_size);
PROVIDE(__vcore_unpg_ro_size = __flatmap_unpg_ro_size);
#else
PROVIDE(__vcore_unpg_rx_size = __flatmap_unpg_rx_size +
				__flatmap_unpg_ro_size);
PROVIDE(__vcore_unpg_ro_size = 0);
#endif

/* Unpaged read-write memory */
PROVIDE(__vcore_unpg_rw_start = __flatmap_unpg_rw_start);
PROVIDE(__vcore_unpg_rw_size = __flatmap_unpg_rw_size);

#ifdef CFG_WITH_PAGER
/*
 * Core init mapping shall cover up to end of the physical RAM.
 * This is required since the hash table is appended to the
 * binary data after the firmware build sequence.
 */
#define __FLATMAP_PAGER_TRAILING_SPACE	\
	(CFG_TEE_RAM_START + CFG_TEE_RAM_PH_SIZE - \
		(__flatmap_init_ro_start + __flatmap_init_ro_size))

/* Paged/init read-only memories */
PROVIDE(__vcore_init_rx_start = __flatmap_init_rx_start);
PROVIDE(__vcore_init_ro_start = __flatmap_init_ro_start);
#ifdef CFG_CORE_RODATA_NOEXEC
PROVIDE(__vcore_init_rx_size = __flatmap_init_rx_size);
PROVIDE(__vcore_init_ro_size = __flatmap_init_ro_size +
				__FLATMAP_PAGER_TRAILING_SPACE);
#else
PROVIDE(__vcore_init_rx_size = __flatmap_init_rx_size +
				__flatmap_init_ro_size +
				__FLATMAP_PAGER_TRAILING_SPACE);
PROVIDE(__vcore_init_ro_size = 0);
#endif /* CFG_CORE_RODATA_NOEXEC */
#endif /* CFG_WITH_PAGER */
