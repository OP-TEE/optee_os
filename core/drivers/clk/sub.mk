srcs-$(CFG_DRIVERS_CLK_CORE) += clk.c
srcs-$(_CFG_DRIVERS_CLK_WEAK) += clk_weak.c
srcs-$(CFG_DRIVERS_CLK_DT) += clk_dt.c
srcs-$(CFG_DRIVERS_CLK_FIXED) += fixed_clk.c
