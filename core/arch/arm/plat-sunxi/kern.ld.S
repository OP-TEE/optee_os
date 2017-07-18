/*
 * Copyright (c) 2014, Allwinner Technology Co., Ltd.
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

OUTPUT_FORMAT(CFG_KERN_LINKER_FORMAT)
OUTPUT_ARCH(CFG_KERN_LINKER_ARCH)

ENTRY(_start)
SECTIONS
{
	. = TEE_RAM_START;
	__flatmap_unpg_rx_start = .;

	/* text/read-only data */
	.text : {
		__text_start = .;
		KEEP(*(.text.head))
		KEEP(*(.text.boot.vectab1))
		KEEP(*(.text.boot.vectab2))
		KEEP(*(.text.boot))
		*(.text* .sram.text.glue_7* .gnu.linkonce.t.*)
		__text_end = .;

		. = ALIGN(4);
		__initcall_start = .;
		*(.initcall1)
		*(.initcall2)
		*(.initcall3)
		*(.initcall4)
		__initcall_end = .;
	}

#ifdef CFG_CORE_RODATA_NOEXEC
	. = ALIGN(SMALL_PAGE_SIZE);
#endif
	__flatmap_unpg_rx_size = . - __flatmap_unpg_rx_start;
	__flatmap_unpg_ro_start = .;


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
	__exidx_start = .;
	.ARM.exidx : { *(.ARM.exidx* .gnu.linkonce.armexidx.*) }
	__exidx_end = .;

	.ARM.extab : {
		__extab_start = .;
		*(.ARM.extab*)
		__extab_end = .;
	}

	.rodata : ALIGN(4) {
		__rodata_start = .;
		*(.rodata .rodata.* .gnu.linkonce.r.*)

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
		__start_phys_nsec_ddr_section = . ;
		KEEP(*(phys_nsec_ddr_section))
		__end_phys_nsec_ddr_section = . ;

		. = ALIGN(4);
		__rodata_end = .;
	}

	/* Start page aligned read-write memory */
#ifdef CFG_CORE_RWDATA_NOEXEC
	. = ALIGN(SMALL_PAGE_SIZE);
#endif
	__flatmap_unpg_ro_size = . - __flatmap_unpg_ro_start;
	__flatmap_unpg_rw_start = .;

	.data : ALIGN(4) {
		/* writable data  */
		__data_start_rom = .;
		/* in one segment binaries, the rom data address is on top of the ram data address */
		__data_start = .;
		*(.data .data.* .gnu.linkonce.d.*)
	}

	.ctors : ALIGN(4) {
		__ctor_list = .;
		*(.ctors)
		__ctor_end = .;
	}
	.dtors : ALIGN(4) {
		__dtor_list = .;
		*(.dtors)
		__dtor_end = .;
	}
	.got : { *(.got.plt) *(.got) }
	.dynamic : { *(.dynamic) }

	__data_end = .;

	/* unintialized data (in same segment as writable data) */
	.bss : ALIGN(4) {
		KEEP(*(.bss.prebss.*))
		. = ALIGN(4);
		__bss_start = .;
		*(.bss .bss.*)
		*(.gnu.linkonce.b.*)
		*(COMMON)
		. = ALIGN(4);
		__bss_end = .;
	}

        /*
	 * Uninitialized data that shouldn't be zero initialized at
	 * runtime.
	 *
	 * L1 mmu table requires 16 KiB alignment
	 */
	.nozi : ALIGN(16 * 1024) {
		__nozi_pad_end = .;
		KEEP(*(.nozi .nozi.*))
	}

	teecore_heap_start = .;
	. += 0x40000 /*256KiB*/;
	teecore_heap_end = .;

	_end = .;

	. = TEE_RAM_START + TEE_RAM_SIZE;
	_end_of_ram = .;

	__flatmap_unpg_rw_size = _end_of_ram - __flatmap_unpg_rw_start;

	/* Strip unnecessary stuff */
	/DISCARD/ : { *(.comment .note .eh_frame) }
}

/* Read-only memories */
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

/* Read-write memory */
PROVIDE(__vcore_unpg_rw_start = __flatmap_unpg_rw_start);
PROVIDE(__vcore_unpg_rw_size = __flatmap_unpg_rw_size);
