srcs-y += regulator.c
srcs-$(CFG_DT) += regulator_dt.c
srcs-$(CFG_REGULATOR_FIXED) += regulator_fixed.c
srcs-$(CFG_STM32_VREFBUF) += stm32_vrefbuf.c
