#ifdef ARM32
OUTPUT_FORMAT("elf32-littlearm")
OUTPUT_ARCH(arm)
#endif
#ifdef ARM64
OUTPUT_FORMAT("elf64-littleaarch64")
OUTPUT_ARCH(aarch64)
#endif

PHDRS {
	rodata PT_LOAD;
	rwdata PT_LOAD;
	rodata2 PT_LOAD;
	dyn PT_DYNAMIC;
}

SECTIONS {
	.ta_head : {*(.ta_head)} :rodata

	.text : {
		*(.text .text.*)
		*(.stub)
		*(.glue_7)
		*(.glue_7t)
		*(.gnu.linkonce.t.*)
		/* Workaround for an erratum in ARM's VFP11 coprocessor */
		*(.vfp11_veneer)
	}
	.eh_frame : { *(.eh_frame) }
	.rodata : {
		*(.gnu.linkonce.r.*)
		*(.rodata .rodata.*)
	}
	/* .ARM.exidx is sorted, so has to go in its own output section.  */
	.ARM.exidx : { *(.ARM.exidx* .gnu.linkonce.armexidx.*) }

        .ctors : { *(.ctors) }
        .dtors : { *(.dtors) }
        .plt : { *(.plt) }
	.got : { *(.got.plt) *(.got) }

	.rel.text : { *(.rel.text) *(.rel.gnu.linkonce.t*) }
	.rela.text : { *(.rela.text) *(.rela.gnu.linkonce.t*) }
	.rel.data : { *(.rel.data) *(.rel.gnu.linkonce.d*) }
	.rela.data : { *(.rela.data) *(.rela.gnu.linkonce.d*) }
	.rel.rodata : { *(.rel.rodata) *(.rel.gnu.linkonce.r*) }
	.rela.rodata : { *(.rela.rodata) *(.rela.gnu.linkonce.r*) }
	.rel.dyn : { *(.rel.dyn) }
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

	/* Page align to allow dropping execute bit for RW data */
	. = ALIGN(4096);

	.data : { *(.data .data.* .gnu.linkonce.d.*) } :rwdata

	.bss : { *(.bss .bss.* .gnu.linkonce.b.* COMMON) }

	/* Page align to separate from RW data */
	. = ALIGN(4096);

	.dynamic : { *(.dynamic) } :dyn :rodata2
	.dynsym : { *(.dynsym) } :rodata2
	.dynstr : { *(.dynstr) }
	.hash : { *(.hash) }

	/DISCARD/ : { *(.interp) }

	linker_RO_sections_size = 12;
	linker_RW_sections_size = 12;
	linker_res_funcs_ZI_sections_size = 12;
	linker_rel_dyn_GOT = 12;
}

