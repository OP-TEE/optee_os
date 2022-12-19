srcs-y += spinlock.S
srcs-y += idle.c
srcs-$(CFG_RISCV_TIME_SOURCE_RDTIME) += tee_time_rdtime.c
srcs-$(CFG_RISCV_SBI) += sbi.c
srcs-$(CFG_RISCV_SBI_CONSOLE) += sbi_console.c
srcs-y += boot.c
srcs-y += entry.S
asm-defines-y += asm-defines.c
