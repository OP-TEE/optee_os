# SPDX-License-Identifier: BSD-2-Clause
srcs-$(CFG_CORE_CRYPTO_AES_ACCEL) += aes_rv_glue.c
srcs-$(CFG_CORE_CRYPTO_AES_ACCEL) += aes_subword_rv.S
srcs-$(CFG_CORE_CRYPTO_AES_ACCEL) += aes_modes_rv.S
srcs-$(CFG_CORE_CRYPTO_AES_ACCEL) += aes_ctr_rv.S
srcs-$(CFG_CORE_CRYPTO_AES_ACCEL) += aes_xts_rv.S
