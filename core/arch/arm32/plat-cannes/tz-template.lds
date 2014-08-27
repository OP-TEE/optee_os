OUTPUT_ARCH(arm)
ENTRY(tz_sinit)

MEMORY
{
    /* 1 MByte is allocated for teecore execution */
    EXEC_MEM   (rw) : ORIGIN = (%in_TEE_SCATTER_START% + 0x00000000), LENGTH = 0x000D0000
    STACKS_MEM (rw) : ORIGIN = (%in_TEE_SCATTER_START% + 0x000D0000), LENGTH = 0x00010000
    CTX_MEM    (rw) : ORIGIN = (%in_TEE_SCATTER_START% + 0x000E0000), LENGTH = 0x00010000
    MMU_MEM    (rw) : ORIGIN = (%in_TEE_SCATTER_START% + 0x000F0000), LENGTH = 0x00010000
}

SECTIONS
{
    .teecore_exec :
    {
        *(.vector_table)
        *(.text); *(.text.*)
        *(.rodata); *(.rodata.*)
        *(.got); *(.got.*)
        *(.data); *(.data.*)

        __start_ta_head_section = . ;
        *(ta_head_section)
        __stop_ta_head_section = . ;

        __bss_start = (.) ;
        *(.bss)
        __bss_end = (.) ;

        *(COMMON)

    } > EXEC_MEM

    .stacks :
    {
        __stacks_start = (.);
	*(.bss.prebss.stack)
    } > STACKS_MEM

    /* NSec and Secure context storage (TODO: move in C-code) */
    .context_backup :
    {
        PUB_CONTEXT_BACKUP  = (. + 0x000); /* Public context backup area */
        SEC_CONTEXT_BACKUP  = (. + 0x400); /* Secure context backup area */
    } > CTX_MEM

    /* MMU pages tables (TODO: should we keep them cachable?) */
    .pagestables :
    {
        SEC_MMU_TTB_FLD    = (.);           /* MMU L1 table for teecore: 16kB */
        SEC_MMU_TTB_SLD    = (. + 0x4000);  /* MMU L2 tables for teecore: 16*1kB (16MB mappeable) */
        SEC_TA_MMU_TTB_FLD = (. + 0x8000);  /* MMU L1 table for TAs: 16kB */
        SEC_TA_MMU_TTB_SLD = (. + 0xC000);  /* MMU L2 tables for TAs:: 16*1kB (16MB mappeable) */
        SEC_MMU_TTB_END    = (. + 0x10000); /* end of teecore and TAs MMU tables */
    } > MMU_MEM
}

    /* 64kB aligned heap start between BSS and secure stacks */
    PROVIDE(teecore_heap_start = __bss_end);
    PROVIDE(teecore_heap_end = __stacks_start);

