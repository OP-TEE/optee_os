srcs-y += core_mmu_arch.c
ifeq ($(CFG_SYSCALL_FTRACE),y)
cflags-remove-core_mmu_arch.c-y += -pg
endif
srcs-y += pgt_cache.c
srcs-y += tlb_helpers_rv.S
