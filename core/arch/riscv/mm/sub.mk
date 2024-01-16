srcs-y += core_mmu_arch.c
srcs-y += tlb_helpers_rv.S

ifeq ($(CFG_SYSCALL_FTRACE),y)
# We would not like to profile MMU APIs as these are used to switch TA
# context which may cause undesired behaviour as ftrace requires TA context
# to be active. Moreover profiling code uses some of MMU APIs to check
# if TA context is active or not.
cflags-remove-core_mmu_arch.c-y += -pg
endif
