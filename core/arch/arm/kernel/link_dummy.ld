/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2017, Linaro Limited
 */

SECTIONS
{
	/*
	 * This seems to make the ARMv7 linker happy with regards to glue_7
	 * sections etc.
	 */
	..dummy : { }
}

__asan_map_end = .;
__asan_map_size = .;
__asan_map_start = .;
__asan_shadow_end = .;
__asan_shadow_size = .;
__asan_shadow_start = .;
__bss_end = .;
__bss_start = .;
__ctor_end = .;
__ctor_list = .;
__data_end = .;
__data_start = .;
__end = .;
__end_phys_ddr_overall_section = .;
__end_phys_mem_map_section = .;
__end_phys_nsec_ddr_section = .;
__end_phys_sdp_mem_section = .;
__exidx_end = .;
__exidx_start = .;
__extab_end = .;
__extab_start = .;
__heap1_end = .;
__heap1_start = .;
__heap2_end = .;
__heap2_start = .;
__identity_map_init_end = .;
__identity_map_init_start = .;
__initcall_end = .;
__initcall_start = .;
__init_end = .;
__init_size = .;
__init_start = .;
__nex_bss_end = .;
__nex_bss_start = .;
__nex_heap_end = .;
__nex_heap_start = .;
__nozi_end = .;
__nozi_stack_end = .;
__nozi_stack_start = .;
__nozi_start = .;
__pageable_end = .;
__pageable_part_end = .;
__pageable_part_start = .;
__pageable_start = .;
__rela_end = .;
__rela_start = .;
__rel_end = .;
__rel_start = .;
__rodata_early_ta_end = .;
__rodata_early_ta_start = .;
__rodata_end = .;
__rodata_start = .;
__start_phys_ddr_overall_section = .;
__start_phys_nsec_ddr_section = .;
__text_init_start = .;
__text_start = .;
__tmp_hashes_end = .;
__tmp_hashes_size = .;
__tmp_hashes_start = .;
__vcore_init_ro_end = .;
__vcore_init_ro_size = .;
__vcore_init_ro_start = .;
__vcore_init_rx_end = .;
__vcore_init_rx_size = .;
__vcore_init_rx_start = .;
__vcore_nex_rw_end = .;
__vcore_nex_rw_size = .;
__vcore_nex_rw_start = .;
__vcore_unpg_ro_end = .;
__vcore_unpg_ro_size = .;
__vcore_unpg_ro_start = .;
__vcore_unpg_rw_end = .;
__vcore_unpg_rw_size = .;
__vcore_unpg_rw_start = .;
__vcore_unpg_rx_end = .;
__vcore_unpg_rx_size = .;
__vcore_unpg_rx_start = .;
PROVIDE(core_v_str = 0);
PROVIDE(tee_entry_std = 0);
PROVIDE(init_teecore = 0);
