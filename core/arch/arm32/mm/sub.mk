srcs-y += core_mmu.c
srcs-y += tee_pager.c
srcs-y += tee_mmu.c
srcs-$(WITH_MMU_COARSE) += tee_mmu_coarse.c
srcs-$(WITH_MMU_SECTION) += tee_mmu_section.c
srcs-y += tee_mm.c
srcs-y += tee_mm_unpg.c
srcs-y += tee_mmu_unpg.c
