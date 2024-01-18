/* SPDX-License-Identifier: (BSD-2-Clause AND MIT) */
/*
 * Copyright 2022-2023 NXP
 */

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
	/* Ensure text section is page aligned */
	ASSERT(!(TEE_LOAD_ADDR & (SMALL_PAGE_SIZE - 1)),
	       "text start should align to 4Kb")

	__text_start = .;

	/*
	 * Memory between TEE_LOAD_ADDR and page aligned rounded down
	 * value will be mapped with unpaged "text" section attributes:
	 * likely to be read-only/executable.
	 */
	__flatmap_rx_start = LD_ROUNDDOWN(__text_start, SMALL_PAGE_SIZE);

	.text : {
		KEEP(*(.text._start))
		__identity_map_init_start = .;
		__text_data_start = .;
		*(.identity_map.data)
		__text_data_end = .;
		*(.identity_map .identity_map.*)
		__identity_map_init_end = .;
		*(.text .text.*)
		*(.sram.text.glue_7* .gnu.linkonce.t.*)
		. = ALIGN(8);
	}
	__text_end = .;

#ifdef CFG_CORE_RODATA_NOEXEC
	. = ALIGN(SMALL_PAGE_SIZE);
#endif
	__flatmap_rx_size = . - __flatmap_rx_start;
	__flatmap_ro_start = .;

	.rodata : ALIGN(8) {
		__rodata_start = .;
		*(.gnu.linkonce.r.*)
		*(.rodata .rodata.*)
#ifndef CFG_CORE_ASLR
		. = ALIGN(8);
		KEEP(*(SORT(.scattered_array*)));
#endif
		. = ALIGN(8);
		__rodata_end = .;
	}

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

	/* Start page aligned read-write memory */
#ifdef CFG_CORE_RWDATA_NOEXEC
	. = ALIGN(SMALL_PAGE_SIZE);
#endif
	__flatmap_ro_size = . - __flatmap_ro_start;
	__flatmap_rw_start = .;

	.data : ALIGN(8) {
		/* writable data  */
		__data_start_rom = .;
		/* in one segment binaries, the rom data address is on top
		   of the ram data address */
		__data_start = .;
		*(.data .data.* .gnu.linkonce.d.*)
		. = ALIGN(8);
		/*
		 * To allow the linker relax accesses to global symbols,
		 * those need to be within imm12 (signed 12-bit) offsets
		 * from __global_pointer$.
		 */
		PROVIDE(__global_pointer$ = . + 0x800 );
		*(.sdata .sdata.* .gnu.linkonce.s.*)
	}

	/* uninitialized data */
	.bss : {
		__data_end = .;
		__bss_start = .;
		*(.sbss .sbss.*)
		*(.gnu.linkonce.sb.*)
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
		. += CFG_CORE_HEAP_SIZE;
		. = ALIGN(4 * 1024);
		__heap1_end = .;
	}
	/*
	 * Uninitialized data that shouldn't be zero initialized at
	 * runtime.
	 */
	.nozi (NOLOAD) : {
		__nozi_start = .;
		KEEP(*(.nozi .nozi.*))
		. = ALIGN(16);
		__nozi_end = .;
		__nozi_stack_start = .;
		KEEP(*(.nozi_stack .nozi_stack.*))
		. = ALIGN(8);
		__nozi_stack_end = .;
	}

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
	__init_size = __data_end - TEE_LOAD_ADDR;

	/*
	 * Guard against moving the location counter backwards in the assignment
	 * below.
	 */
	ASSERT(. <= (TEE_RAM_START + TEE_RAM_VA_SIZE),
		"TEE_RAM_VA_SIZE is too small")
	. = TEE_RAM_START + TEE_RAM_VA_SIZE;

	_end_of_ram = .;

	__flatmap_rw_size = _end_of_ram - __flatmap_rw_start;
	__get_tee_init_end = .;

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
#ifndef CFG_CORE_ASLR
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
__vcore_unpg_rx_start = __flatmap_rx_start;
__vcore_unpg_ro_start = __flatmap_ro_start;
#ifdef CFG_CORE_RODATA_NOEXEC
__vcore_unpg_rx_size = __flatmap_rx_size;
__vcore_unpg_ro_size = __flatmap_ro_size;
#else
__vcore_unpg_rx_size = __flatmap_rx_size + __flatmap_ro_size;
__vcore_unpg_ro_size = 0;
#endif
__vcore_unpg_rx_end = __vcore_unpg_rx_start + __vcore_unpg_rx_size;
__vcore_unpg_ro_end = __vcore_unpg_ro_start + __vcore_unpg_ro_size;

/* Unpaged read-write memory */
__vcore_unpg_rw_start = __flatmap_rw_start;
__vcore_unpg_rw_size = __flatmap_rw_size;
__vcore_unpg_rw_end = __vcore_unpg_rw_start + __vcore_unpg_rw_size;

#ifdef CFG_CORE_SANITIZE_KADDRESS
__asan_map_start = (__asan_shadow_start / SMALL_PAGE_SIZE) *
		   SMALL_PAGE_SIZE;
__asan_map_end = ((__asan_shadow_end - 1) / SMALL_PAGE_SIZE) *
		 SMALL_PAGE_SIZE + SMALL_PAGE_SIZE;
__asan_map_size = __asan_map_end - __asan_map_start;
#endif /*CFG_CORE_SANITIZE_KADDRESS*/
