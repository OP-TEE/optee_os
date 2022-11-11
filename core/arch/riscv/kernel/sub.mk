srcs-y += spinlock.S
srcs-y += idle.c
srcs-y += tee_time.c
srcs-$(CFG_RISCV_SBI) += sbi.c
