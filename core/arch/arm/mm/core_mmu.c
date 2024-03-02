// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2016, Linaro Limited
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

#include <arm.h>
#include <assert.h>
#include <bitstring.h>
#include <config.h>
#include <kernel/cache_helpers.h>
#include <kernel/spinlock.h>
#include <kernel/tee_l2cc_mutex.h>
#include <kernel/tlb_helpers.h>
#include <kernel/tz_ssvce_pl310.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <platform_config.h>
#include <trace.h>
#include <util.h>

/*
 * Two ASIDs per context, one for kernel mode and one for user mode. ASID 0
 * and 1 are reserved and not used. This means a maximum of 126 loaded user
 * mode contexts. This value can be increased but not beyond the maximum
 * ASID, which is architecture dependent (max 255 for ARMv7-A and ARMv8-A
 * Aarch32). This constant defines number of ASID pairs.
 */
#define MMU_NUM_ASID_PAIRS		64

static bitstr_t bit_decl(g_asid, MMU_NUM_ASID_PAIRS) __nex_bss;
static unsigned int g_asid_spinlock __nex_bss = SPINLOCK_UNLOCK;

void tlbi_va_range(vaddr_t va, size_t len, size_t granule)
{
	assert(granule == CORE_MMU_PGDIR_SIZE || granule == SMALL_PAGE_SIZE);
	assert(!(va & (granule - 1)) && !(len & (granule - 1)));

	dsb_ishst();
	while (len) {
		tlbi_va_allasid_nosync(va);
		len -= granule;
		va += granule;
	}
	dsb_ish();
	isb();
}

void tlbi_va_range_asid(vaddr_t va, size_t len, size_t granule, uint32_t asid)
{
	assert(granule == CORE_MMU_PGDIR_SIZE || granule == SMALL_PAGE_SIZE);
	assert(!(va & (granule - 1)) && !(len & (granule - 1)));

	dsb_ishst();
	while (len) {
		tlbi_va_asid_nosync(va, asid);
		len -= granule;
		va += granule;
	}
	dsb_ish();
	isb();
}

TEE_Result cache_op_inner(enum cache_op op, void *va, size_t len)
{
	switch (op) {
	case DCACHE_CLEAN:
		dcache_op_all(DCACHE_OP_CLEAN);
		break;
	case DCACHE_AREA_CLEAN:
		dcache_clean_range(va, len);
		break;
	case DCACHE_INVALIDATE:
		dcache_op_all(DCACHE_OP_INV);
		break;
	case DCACHE_AREA_INVALIDATE:
		dcache_inv_range(va, len);
		break;
	case ICACHE_INVALIDATE:
		icache_inv_all();
		break;
	case ICACHE_AREA_INVALIDATE:
		icache_inv_range(va, len);
		break;
	case DCACHE_CLEAN_INV:
		dcache_op_all(DCACHE_OP_CLEAN_INV);
		break;
	case DCACHE_AREA_CLEAN_INV:
		dcache_cleaninv_range(va, len);
		break;
	default:
		return TEE_ERROR_NOT_IMPLEMENTED;
	}
	return TEE_SUCCESS;
}

#ifdef CFG_PL310
TEE_Result cache_op_outer(enum cache_op op, paddr_t pa, size_t len)
{
	TEE_Result ret = TEE_SUCCESS;
	uint32_t exceptions = thread_mask_exceptions(THREAD_EXCP_FOREIGN_INTR);
	vaddr_t pl310_base_pa_op = 0;

	/*
	 * According the ARM PL310 documentation, if the operation is specific
	 * to the PA, the behavior is presented in the following manner:
	 * - Secure access: The data in the cache is only affected by the
	 * operation if it is secure.
	 * - Non-secure access: The data in the cache is only affected by the
	 * operation if it is non-secure.
	 *
	 * https://developer.arm.com/documentation/ddi0246/a/programmer-s-model/register-descriptions/register-7--cache-maintenance-operations
	 *
	 * Depending on the buffer location, use the secure or non-secure PL310
	 * base address to do physical address based cache operation on the
	 * buffer.
	 */
	if (tee_pbuf_is_sec(pa, len))
		pl310_base_pa_op = pl310_base();
	else
		pl310_base_pa_op = pl310_nsbase();

	tee_l2cc_mutex_lock();
	switch (op) {
	case DCACHE_INVALIDATE:
		arm_cl2_invbyway(pl310_base());
		break;
	case DCACHE_AREA_INVALIDATE:
		if (len)
			arm_cl2_invbypa(pl310_base_pa_op, pa, pa + len - 1);
		break;
	case DCACHE_CLEAN:
		arm_cl2_cleanbyway(pl310_base());
		break;
	case DCACHE_AREA_CLEAN:
		if (len)
			arm_cl2_cleanbypa(pl310_base_pa_op, pa, pa + len - 1);
		break;
	case DCACHE_CLEAN_INV:
		arm_cl2_cleaninvbyway(pl310_base());
		break;
	case DCACHE_AREA_CLEAN_INV:
		if (len)
			arm_cl2_cleaninvbypa(pl310_base_pa_op, pa,
					     pa + len - 1);
		break;
	default:
		ret = TEE_ERROR_NOT_IMPLEMENTED;
	}

	tee_l2cc_mutex_unlock();
	thread_unmask_exceptions(exceptions);
	return ret;
}
#endif /*CFG_PL310*/

unsigned int asid_alloc(void)
{
	uint32_t exceptions = cpu_spin_lock_xsave(&g_asid_spinlock);
	unsigned int r;
	int i;

	bit_ffc(g_asid, MMU_NUM_ASID_PAIRS, &i);
	if (i == -1) {
		r = 0;
	} else {
		bit_set(g_asid, i);
		r = (i + 1) * 2;
	}

	cpu_spin_unlock_xrestore(&g_asid_spinlock, exceptions);
	return r;
}

void asid_free(unsigned int asid)
{
	uint32_t exceptions = cpu_spin_lock_xsave(&g_asid_spinlock);

	/* Only even ASIDs are supposed to be allocated */
	assert(!(asid & 1));

	if (asid) {
		int i = (asid - 1) / 2;

		assert(i < MMU_NUM_ASID_PAIRS && bit_test(g_asid, i));
		bit_clear(g_asid, i);
	}

	cpu_spin_unlock_xrestore(&g_asid_spinlock, exceptions);
}

bool arch_va2pa_helper(void *va, paddr_t *pa)
{
	uint32_t exceptions = thread_mask_exceptions(THREAD_EXCP_ALL);
	paddr_t par = 0;
	paddr_t par_pa_mask = 0;
	bool ret = false;

#ifdef ARM32
	write_ats1cpr((vaddr_t)va);
	isb();
#ifdef CFG_WITH_LPAE
	par = read_par64();
	par_pa_mask = PAR64_PA_MASK;
#else
	par = read_par32();
	par_pa_mask = PAR32_PA_MASK;
#endif
#endif /*ARM32*/

#ifdef ARM64
	write_at_s1e1r((vaddr_t)va);
	isb();
	par = read_par_el1();
	par_pa_mask = PAR_PA_MASK;
#endif
	if (par & PAR_F)
		goto out;
	*pa = (par & (par_pa_mask << PAR_PA_SHIFT)) |
		((vaddr_t)va & (BIT64(PAR_PA_SHIFT) - 1));

	ret = true;
out:
	thread_unmask_exceptions(exceptions);
	return ret;
}

bool cpu_mmu_enabled(void)
{
	uint32_t sctlr;

#ifdef ARM32
	sctlr =  read_sctlr();
#else
	sctlr =  read_sctlr_el1();
#endif

	return sctlr & SCTLR_M ? true : false;
}
