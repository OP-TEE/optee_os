srcs-y += spinlock.S
srcs-y += cache_helpers_rv.S
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
asm-defines-y += asm-defines.c
