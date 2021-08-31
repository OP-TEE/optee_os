// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2017-2021, Linaro Limited
 */
#include <compiler.h>
#include <initcall.h>
#include <kernel/boot.h>
#include <kernel/thread.h>
#include <kernel/ts_manager.h>
#include <kernel/wait_queue.h>
#include <mm/fobj.h>
#include <mm/mobj.h>
#include <tee_api_types.h>
#include <tee/entry_std.h>

#include "thread_private.h"

void __section(".text.dummy.call_preinitcalls") call_preinitcalls(void)
{
}

void __section(".text.dummy.call_initcalls") call_initcalls(void)
{
}

void __section(".text.dummy.call_finalcalls") call_finalcalls(void)
{
}

void __section(".text.dummy.boot_init_primary_late")
boot_init_primary_late(unsigned long fdt __unused)
{
}

uint32_t __section(".text.dummy.__thread_std_smc_entry")
__thread_std_smc_entry(uint32_t a0 __unused, uint32_t a1 __unused,
		       uint32_t a2 __unused, uint32_t a3 __unused,
		       uint32_t a4 __unused, uint32_t a5 __unused)
{
	return 0;
}

const struct mobj_ops mobj_reg_shm_ops __rodata_dummy;
const struct mobj_ops mobj_ffa_ops __rodata_dummy;
const struct mobj_ops mobj_phys_ops __rodata_dummy;
const struct mobj_ops mobj_virt_ops __rodata_dummy;
const struct mobj_ops mobj_mm_ops __rodata_dummy;
const struct mobj_ops mobj_shm_ops __rodata_dummy;
const struct mobj_ops mobj_seccpy_shm_ops __rodata_dummy;
const struct mobj_ops mobj_with_fobj_ops __rodata_dummy;
const struct fobj_ops ops_rwp_paged_iv __rodata_dummy;
const struct fobj_ops ops_rwp_unpaged_iv __rodata_dummy;
const struct fobj_ops ops_ro_paged __rodata_dummy;
const struct fobj_ops ops_ro_reloc_paged __rodata_dummy;
const struct fobj_ops ops_locked_paged __rodata_dummy;
const struct fobj_ops ops_sec_mem __rodata_dummy;
const struct ts_ops user_ta_ops __rodata_dummy;
const struct ts_ops stmm_sp_ops __rodata_dummy;
const struct ts_ops sp_ops __rodata_dummy;
