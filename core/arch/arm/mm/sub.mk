srcs-y += core_mmu.c
srcs-$(CFG_WITH_PAGER) += tee_pager.c
ifeq ($(CFG_WITH_LPAE),y)
srcs-y += core_mmu_lpae.c
else
srcs-y += core_mmu_v7.c
endif
srcs-y += tee_mm.c
srcs-y += pgt_cache.c
srcs-$(CFG_CORE_FFA) += mobj_ffa.c
srcs-$(CFG_SECURE_PARTITION) += sp_mem.c
ifneq ($(CFG_CORE_FFA),y)
srcs-$(CFG_CORE_DYN_SHM) += mobj_dyn_shm.c
endif

ifeq ($(CFG_SYSCALL_FTRACE),y)
# We would not like to profile MMU APIs as these are used to switch TA
# context which may cause undesired behaviour as ftrace requires TA context
# to be active. Moreover profiling code uses some of MMU APIs to check
# if TA context is active or not.
ifeq ($(CFG_WITH_LPAE),y)
cflags-remove-core_mmu_lpae.c-y += -pg
else
cflags-remove-core_mmu_v7.c-y += -pg
endif
endif
