srcs-y += spinlock.S
srcs-y += cache_helpers_rv.S
srcs-y += csr_detect.S
srcs-y += idle.c
srcs-$(CFG_RISCV_TIME_SOURCE_RDTIME) += tee_time_rdtime.c
srcs-$(CFG_RISCV_SBI) += sbi.c
srcs-$(CFG_RISCV_SBI_CONSOLE) += sbi_console.c
srcs-y += boot.c
srcs-y += entry.S
srcs-y += abort.c
srcs-y += thread_rv.S
srcs-y += thread_arch.c
srcs-y += arch_scall_rv.S
srcs-y += arch_scall.c
srcs-$(CFG_UNWIND) += unwind_rv.c
srcs-$(CFG_SEMIHOSTING) += semihosting_rv.S
srcs-y += thread_optee_abi.c
srcs-y += thread_optee_abi_rv.S
asm-defines-y += asm-defines.c

ifeq ($(CFG_SYSCALL_FTRACE),y)
# We would not like to profile thread.c file as it provide common APIs
# that are needed for ftrace framework to trace syscalls. So profiling
# this file could create an incorrect cyclic behaviour.
cflags-remove-thread_arch.c-y += -pg
# Tracing abort dump files corrupts the stack trace. So exclude them
# from profiling.
cflags-remove-abort.c-y += -pg
ifeq ($(CFG_UNWIND),y)
cflags-remove-unwind_rv.c-y += -pg
endif
endif
