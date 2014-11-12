OUTPUT_ARCH(arm)
ENTRY(tz_sinit)

MEMORY
{
    /* 1 MByte is allocated for teecore execution */
    EXEC_MEM     (rw) : ORIGIN = (%in_TEE_SCATTER_START% + 0x00000000), LENGTH = 0x000E0000
    /* check stacks sizes from main.c */
    STACKS_MEM   (rw) : ORIGIN = (%in_TEE_SCATTER_START% + 0x000E0000), LENGTH = 0x00018000
    MMU_UTA_MEM  (rw) : ORIGIN = (%in_TEE_SCATTER_START% + 0x000FBF80), LENGTH = 0x00000080
    MMU_CORE_MEM (rw) : ORIGIN = (%in_TEE_SCATTER_START% + 0x000FC000), LENGTH = 0x00004000
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
	*(.nozi.stack)
    } > STACKS_MEM

    /* MMU pages tables (TODO: should we keep them cachable?) */
    .mmu_uta :
    {
        SEC_TA_MMU_TTB_FLD = (.);	 /* MMU L1 table for TAs: 128B */
        SEC_TA_MMU_TTB_END = (. + 0x80);
    } > MMU_UTA_MEM
    .mmu_core :
    {
        SEC_MMU_TTB_FLD = (.);           /* MMU L1 table for teecore: 16kB */
        SEC_MMU_TTB_END = (. + 0x4000);
    } > MMU_CORE_MEM

}

    /* 64kB aligned heap start between BSS and secure stacks */
    PROVIDE(teecore_heap_start = __bss_end);
    PROVIDE(teecore_heap_end = __stacks_start);

