COMMON_HAL = ../common

incdirs-y += $(COMMON_HAL)
incdirs-y += ../../include
incdirs-y += .

srcs-y += $(COMMON_HAL)/hal_cfg.c
srcs-y += $(COMMON_HAL)/hal_rng.c
srcs-y += $(COMMON_HAL)/hal_jr.c
srcs-y += $(COMMON_HAL)/hal_ctrl.c
srcs-y += hal_clk.c
srcs-y += hal_ctrl.c
srcs-y += hal_jr.c

