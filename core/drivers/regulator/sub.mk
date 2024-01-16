srcs-y += regulator.c
srcs-$(CFG_DT) += regulator_dt.c
srcs-$(CFG_REGULATOR_FIXED) += regulator_fixed.c
srcs-$(CFG_REGULATOR_GPIO) += regulator_gpio.c
srcs-$(CFG_STM32_VREFBUF) += stm32_vrefbuf.c
srcs-$(CFG_STM32MP13_REGULATOR_IOD) += stm32mp13_regulator_iod.c
