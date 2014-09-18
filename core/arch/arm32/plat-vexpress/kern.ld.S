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

OUTPUT_FORMAT(PLATFORM_LINKER_FORMAT)
OUTPUT_ARCH(PLATFORM_LINKER_ARCH)

ENTRY(_start)
SECTIONS
{
	. = TEE_RAM_START;

	/* text/read-only data */
	.text : {
		__text_start = .;
		KEEP(*(.text.boot.vectab1))
		KEEP(*(.text.boot.vectab2))
		KEEP(*(.text.boot))
		*(.text* .sram.text.glue_7* .gnu.linkonce.t.*)
		__text_end = .;
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
	__exidx_start = .;
	.ARM.exidx : { *(.ARM.exidx* .gnu.linkonce.armexidx.*) }
	__exidx_end = .;

	.rodata : ALIGN(4) {
		__rodata_start = .;
		*(.rodata .rodata.* .gnu.linkonce.r.*)
		. = ALIGN(4);

		__start_ta_head_section = . ;
		*(ta_head_section)
		__stop_ta_head_section = . ;

		. = ALIGN(4);
		__rodata_end = .;
	}


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

#if PLATFORM_FLAVOR == PLATFORM_FLAVOR_FVP
	/*
	 * The base address of the coherent memory section must be
	 * page-aligned (4K) to guarantee that the coherent data are stored
	 * on their own pages and are not mixed with normal data.  This is
	 * required to set up the correct memory attributes for the
	 * coherent data page tables.
	 */
	coherent_ram (NOLOAD) : ALIGN(4096) {
		__COHERENT_RAM_START__ = .;
		*(tzfw_coherent_mem)
		__COHERENT_RAM_END_UNALIGNED__ = .;
		/*
		 * Memory page(s) mapped to this section will be marked as
		 * device memory.  No other unexpected data must creep in.
		 * Ensure the rest of the current memory page is unused.
		 */
		. = NEXT(4096);
		__COHERENT_RAM_END__ = .;
	}
#endif

	teecore_heap_start = .;
	. += 0x40000 /*256KiB*/;
	teecore_heap_end = .;

	_end = .;

	. = TEE_RAM_START + TEE_RAM_SIZE;
	_end_of_ram = .;

	/* Strip unnecessary stuff */
	/DISCARD/ : { *(.comment .note .eh_frame) }
}
