#ifdef ARM32
OUTPUT_FORMAT("elf32-littlearm")
OUTPUT_ARCH(arm)
#define MCOUNT_SYM __gnu_mcount_nc
#endif
#ifdef ARM64
OUTPUT_FORMAT("elf64-littleaarch64")
OUTPUT_ARCH(aarch64)
#define MCOUNT_SYM _mcount
#endif

#ifndef CFG_FTRACE_BUF_SIZE
#define CFG_FTRACE_BUF_SIZE 2048
#endif

SECTIONS {
	.text : {
		__text_start = .;
		*(.text .text.*)
		*(.stub)
		*(.glue_7)
		*(.glue_7t)
		*(.gnu.linkonce.t.*)
		/* Workaround for an erratum in ARM's VFP11 coprocessor */
		*(.vfp11_veneer)
		__text_end = .;
	}
	.note.gnu.property : { *(.note.gnu.property) }
        .plt : { *(.plt) }

	.eh_frame_hdr : {
		*(.eh_frame_hdr)
		*(.eh_frame_entry .eh_frame_entry.*)
	}
	.eh_frame : { KEEP(*(.eh_frame)) *(.eh_frame.*) }
	.gcc_except_table : { *(.gcc_except_table .gcc_except_table.*) }
	.rodata : {
		*(.gnu.linkonce.r.*)
		*(.rodata .rodata.*)
	}
	.ARM.extab : { *(.ARM.extab* .gnu.linkonce.armextab.*) }
	/* .ARM.exidx is sorted, so has to go in its own output section.  */
	PROVIDE_HIDDEN(__exidx_start = .);
	.ARM.exidx : { *(.ARM.exidx* .gnu.linkonce.armexidx.*) }
	PROVIDE_HIDDEN(__exidx_end = .);
        .ctors : { *(.ctors) }
        .dtors : { *(.dtors) }
	.dynsym : { *(.dynsym) }
	.dynstr : { *(.dynstr) }
	.hash : { *(.hash) }

	/* Page align to allow dropping execute bit for RW data */
	. = ALIGN(4096);

	.dynamic : { *(.dynamic) }
	.tdata : { *(.tdata .tdata.* .gnu.linkonce.td.*) }
	.tbss : { *(.tbss .tbss.* .gnu.linkonce.tb.*) *(.tcommon) }
	.got : { *(.got.plt) *(.got) }
	.rel.text : { *(.rel.text) *(.rel.gnu.linkonce.t*) }
	.rela.text : { *(.rela.text) *(.rela.gnu.linkonce.t*) }
	.rel.data : { *(.rel.data) *(.rel.gnu.linkonce.d*) }
	.rela.data : { *(.rela.data) *(.rela.gnu.linkonce.d*) }
	.rel.tdata : { *(.rel.tdata .rel.tdata.* .rel.gnu.linkonce.td.*) }
	.rela.tdata : { *(.rela.tdata .rela.tdata.* .rela.gnu.linkonce.td.*) }
	.rel.tbss : { *(.rel.tbss .rel.tbss.* .rel.gnu.linkonce.tb.*) }
	.rela.tbss : { *(.rela.tbss .rela.tbss.* .rela.gnu.linkonce.tb.*) }
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

	.data : { *(.data .data.* .gnu.linkonce.d.*) }
	.bss : {
		*(.bss .bss.* .gnu.linkonce.b.* COMMON)

		/*
		 * TA tracing using ftrace
		 * Reserve some space for the ftrace buffer, only if the
		 * TA is instrumented (i.e., some files were built with -pg).
		 */
		. = ALIGN(8);
		__ftrace_buf_start = .;
		. += DEFINED(MCOUNT_SYM) ?
			CFG_FTRACE_BUF_SIZE : 0;
		__ftrace_buf_end = .;
	}

	/DISCARD/ : { *(.interp) }
}

