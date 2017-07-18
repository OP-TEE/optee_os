/*
 * Copyright (c) 2017, Linaro Limited
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

SECTIONS
{
	/*
	 * This seems to make the ARMv7 linker happy with regards to glue_7
	 * sections etc.
	 */
	..dummy : { }
}

__asan_shadow_end = .;
__asan_shadow_start = .;
__bss_end = .;
__bss_start = .;
__ctor_end = .;
__ctor_list = .;
__data_end = .;
__end = .;
__end_phys_mem_map_section = .;
__end_phys_nsec_ddr_section = .;
__end_phys_sdp_mem_section = .;
__exidx_end = .;
__exidx_start = .;
__heap1_end = .;
__heap1_start = .;
__heap2_end = .;
__heap2_start = .;
__initcall_end = .;
__initcall_start = .;
__init_end = .;
__init_size = .;
__init_start = .;
__nozi_end = .;
__nozi_stack_end = .;
__nozi_stack_start = .;
__nozi_start = .;
__pageable_end = .;
__pageable_part_end = .;
__pageable_part_start = .;
__pageable_start = .;
__rodata_dtdrv_end = .;
__rodata_dtdrv_start = .;
__rodata_end = .;
__rodata_start = .;
__start_phys_nsec_ddr_section = .;
__text_init_start = .;
__text_start = .;
__tmp_hashes_end = .;
__tmp_hashes_size = .;
__tmp_hashes_start = .;
__vcore_init_ro_size = .;
__vcore_init_ro_start = .;
__vcore_init_rx_size = .;
__vcore_init_rx_start = .;
__vcore_unpg_ro_size = .;
__vcore_unpg_ro_start = .;
__vcore_unpg_rw_size = .;
__vcore_unpg_rw_start = .;
__vcore_unpg_rx_size = .;
__vcore_unpg_rx_start = .;
PROVIDE(core_v_str = 0);
PROVIDE(tee_entry_std = 0);
PROVIDE(tee_svc_handler = 0);
PROVIDE(init_teecore = 0);
