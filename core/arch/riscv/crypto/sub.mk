ifeq ($(CFG_CRYPTO_RISCV_WITH_ZVKNED),y)
srcs-y += riscv_aes_zvkned.c
srcs-$(CFG_RV64_core) += riscv_aes_zvkned_a64.S
endif

ifeq ($(CFG_CRYPTO_RISCV_WITH_ZVKNED_ZVKB),y)
srcs-y += riscv_aes_zvkned_zvkb.c
srcs-$(CFG_RV64_core) += riscv_aes_zvkned_zvkb_a64.S
endif
