srcs-y += clk.c
srcs-$(CFG_DRIVERS_CLK_DT) += clk_dt.c
srcs-$(CFG_DRIVERS_CLK_FIXED) += fixed_clk.c
srcs-$(CFG_STM32MP15_CLK) += clk-stm32mp15.c

subdirs-$(CFG_DRIVERS_SAM_CLK) += sam