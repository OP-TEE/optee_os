srcs-y += clk.c
srcs-$(CFG_DRIVERS_CLK_DT) += clk_dt.c
srcs-$(CFG_DRIVERS_CLK_FIXED) += fixed_clk.c
srcs-$(CFG_STM32MP_CLK_CORE) += clk-stm32-core.c
srcs-$(CFG_STM32MP13_CLK) += clk-stm32mp13.c
srcs-$(CFG_STM32MP15_CLK) += clk-stm32mp15.c
srcs-$(CFG_STM32MP21_CLK) += clk-stm32mp21.c
srcs-$(CFG_STM32MP25_CLK) += clk-stm32mp25.c

subdirs-$(CFG_DRIVERS_SAM_CLK) += sam
subdirs-$(CFG_DRIVERS_QCOM_CLK) += qcom
