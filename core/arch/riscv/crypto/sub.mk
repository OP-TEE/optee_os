# SPDX-License-Identifier: BSD-2-Clause
#
# RISC-V crypto_drv implementations are added here as they become available.
#
# The generic crypto library selects these only via CFG_CORE_CRYPTO_*_ACCEL.
# Keep the source selection per algorithm, so a disabled accelerator continues
# to use the libtomcrypt software implementation.
#
srcs-$(CFG_CORE_CRYPTO_SHA256_ACCEL) += sha256_riscv_zvkng_glue.c
srcs-$(CFG_CORE_CRYPTO_SHA256_ACCEL) += sha256-riscv64-zvknha_or_zvknhb-zvkb.S
srcs-$(CFG_CORE_CRYPTO_SHA512_ACCEL) += sha512_riscv_zvkng_glue.c
srcs-$(CFG_CORE_CRYPTO_SHA512_ACCEL) += sha512-riscv64-zvknhb-zvkb.S

# The generic crypto library selects the AES implementation via this option.
srcs-$(CFG_CORE_CRYPTO_AES_ACCEL) += aes_riscv_zvkng_glue.c
srcs-$(CFG_CORE_CRYPTO_AES_ACCEL) += aes-riscv64-zvkned.S
srcs-$(CFG_CORE_CRYPTO_AES_ACCEL) += aes-riscv64-zvkned-zvkb.S
srcs-$(CFG_CORE_CRYPTO_AES_ACCEL) += aes-riscv64-zvkned-zvbb-zvkg.S
