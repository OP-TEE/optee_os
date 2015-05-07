OUTPUT_ARCH(arm)
ENTRY(tz_sinit)

MEMORY
{
    /* 1 MByte is allocated for teecore execution */
    EXEC_MEM     (rw) : ORIGIN = (%in_TEE_SCATTER_START% + 0x00000000), LENGTH = 0x000E0000
    /* check stacks sizes from main.c */
    STACKS_MEM   (rw) : ORIGIN = (%in_TEE_SCATTER_START% + 0x000E0000), LENGTH = 0x00018000
    MMU_UTA_MEM  (rw) : ORIGIN = (%in_TEE_SCATTER_START% + 0x000FBF80), LENGTH = 0x00000080
    MMU_CORE_MEM (rw) : ORIGIN = (%in_TEE_SCATTER_START% + 0x000FC000), LENGTH = 0x00004400
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

	. = ALIGN(4);
	__initcall_start = .;
	*(.initcall1)
	*(.initcall2)
	__initcall_end = .;

        __start_ta_head_section = . ;
        *(ta_head_section)
        __stop_ta_head_section = . ;

        __bss_start = (.) ;
        *(.bss .bss.*)
        __bss_end = (.) ;

        *(COMMON)

    } > EXEC_MEM

    .stacks :
    {
        __stacks_start = (.);
	*(.nozi.stack)
    } > STACKS_MEM

	/*
	 * Uninitialized data that shouldn't be zero initialized at
	 * runtime.
	 *
	 * L1 mmu table requires 16 KiB alignment
	 */
	.nozi (NOLOAD) : ALIGN(16 * 1024) {
		KEEP(*(.nozi .nozi.*))
	}
}

    /* 64kB aligned heap start between BSS and secure stacks */
    PROVIDE(teecore_heap_start = __bss_end);
    PROVIDE(teecore_heap_end = __stacks_start);

