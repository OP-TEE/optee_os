srcs-y += spinlock.S
srcs-y += idle.c
srcs-y += tee_time.c
srcs-$(CFG_RISCV_SBI) += sbi.c
srcs-$(CFG_RISCV_SBI_CONSOLE) += sbi_console.c
srcs-y += boot.c
