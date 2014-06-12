OUTPUT_FORMAT("elf32-littlearm")
OUTPUT_ARCH(arm)

/* The format of the TA binary should be
 *
 * ta_head
 * ta_func_head
 * RO Sections
 * RW Sections
 * ZI Sections
 */

SECTIONS
{
    .ta_head : {*(.ta_head)}
    .ta_func_head : {*(.ta_func_head)}

    /* RO sections */

    start_of_RO_sections = .;

    /*. = 0x00100000 */ /* uTA runs in vmem at 1st MiB */
    .text :
    {
        *(.text .text.*)
        *(.stub)

        /* ARM glue code for ARM and thumb */
        *(.glue_7)
        *(.glue_7t)

        /*
         * The below input sections should not be of use, but put
         * in this output section to define their position.
         */

        /* Workaround for an erratum in ARM's VFP11 coprocessor */
        *(.vfp11_veneer)
        /* ARMv4 interworking compatibility */
        *(.v4_bx)
        /* GCC/ld specific */
        *(.gnu.linkonce.t.*)
        *(.gnu.linkonce.r.*)
        *(.gnu.warning)
        *(.gcc_except_table)
    }
    .rodata :
    {
        *(.rodata .rodata.*)
        *(.rodata1)
        . = ALIGN(4);
    }
    .rel.dyn :
    {
        start_of_rel_data_section = .;
        *(.rel.data)
        *(.rel.data .rel.data.* .rel.gnu.linkonce.d.*)
        end_of_rel_data_section = .;
        start_of_rela_data_section = .;
        *(.rela.data .rela.data.* .rela.gnu.linkonce.d.*)
        end_of_rela_data_section = .;
    }

    . = ALIGN(4);
    end_of_RO_sections = .;

    /* RW sections */

    start_of_RW_sections = .;
    start_of_GOT_sections = .;

    .data :
    {
        *(.got.*)
        *(.got)
        end_of_GOT_sections = .;

        *(.ta_heap_base)

        *(.data .data.*)
        /* GCC/ld specific */
        *(.gnu.linkonce.d.*)
    }
    .data1 : {*(.data1)}
    .tdata : {*(.tdata .tdata.*)}

    end_of_RW_sections = .;

    /* ZI sections */

    start_of_ZI_sections = .;

    .bss :
    {
        *(.dynbss)
        *(.bss .bss.*)
        /* GCC/ld specific */
        *(.gnu.linkonce.b.*)
    }
    .tbss : {*(.tbss .tbss.*)}

    end_of_ZI_sections = .;

    .interp         ALIGN(4) : { *(.interp) }
    .hash           ALIGN(4) : { *(.hash) }
    .dynsym         ALIGN(4) : { *(.dynsym) }
    .dynstr         ALIGN(4) : { *(.dynstr) }
    .gnu.version    ALIGN(4) : { *(.gnu.version) }
    .gnu.version_d  ALIGN(4) : { *(.gnu.version_d) }
    .gnu.version_r  ALIGN(4) : { *(.gnu.version_r) }
    .dynamic        ALIGN(4) : { *(.dynamic) }

    /* Stabs debugging sections.  */
    .stab          : { *(.stab) }
    .stabstr       : { *(.stabstr) }
    .stab.excl     : { *(.stab.excl) }
    .stab.exclstr  : { *(.stab.exclstr) }
    .stab.index    : { *(.stab.index) }
    .stab.indexstr : { *(.stab.indexstr) }
    .comment       : { *(.comment) }

    /*
     * Remove relocation information for GOT and the headers.
     * All needed relocation informtion should already be matched above.
     */
    .junkedrel /*ALIGN(4)*/ :
    {
        *(.rel.*)
        *(.rela.*)
    }

    PROVIDE(linker_RO_sections_size = end_of_RO_sections - start_of_RO_sections);

    linker_RW_sections_size = end_of_RW_sections - start_of_RW_sections;

    ZI_sections_size = end_of_ZI_sections - start_of_ZI_sections;
    ASSERT(ZI_sections_size <= 0xfffff, "Too large ZI_sections_size")
    /*
     * Reserve the last two struct user_ta_func_head elements for the
     * properties
     */
    linker_res_funcs_ZI_sections_size = (2 << 20) + ZI_sections_size;

    GOT_sections_size = end_of_GOT_sections - start_of_GOT_sections;
    rel_sections_size = end_of_rel_data_section - start_of_rel_data_section;
    rela_sections_size = end_of_rela_data_section - start_of_rela_data_section;
    ASSERT(rela_sections_size == 0, "Can't handle nonzero rela_sections_size")
    ASSERT(GOT_sections_size <= 0xffff, "Too large GOT_sections_size")
    ASSERT(rel_sections_size <= 0xffff, "Too large rel_sections_size")
    linker_rel_dyn_GOT = (rel_sections_size << 16) + GOT_sections_size;

}

