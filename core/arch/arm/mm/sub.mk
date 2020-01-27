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
srcs-$(CFG_CORE_DYN_SHM) += mobj_dyn_shm.c

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
