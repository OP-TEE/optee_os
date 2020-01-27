incdirs-y += ../common
incdirs-y += ../../include
incdirs-y += .

srcs-$(CFG_MX6) += hal_clk_mx6.c
srcs-$(CFG_MX7) += hal_clk_mx7.c
srcs-$(CFG_MX7ULP) += hal_clk_mx7ulp.c
srcs-y += hal_ctrl.c
srcs-y += hal_jr.c
