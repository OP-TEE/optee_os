srcs-y += core_mmu.c
srcs-$(CFG_WITH_PAGER) += tee_pager.c
srcs-y += tee_mmu.c
ifeq ($(CFG_WITH_LPAE),y)
srcs-y += core_mmu_lpae.c
else
srcs-y += core_mmu_v7.c
endif
srcs-y += tee_mm.c
srcs-y += pgt_cache.c
srcs-y += mobj.c
