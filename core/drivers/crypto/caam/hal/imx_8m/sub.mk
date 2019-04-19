COMMON_HAL = ../common

incdirs-y += $(COMMON_HAL)/registers
incdirs-y += registers
incdirs-y += ../../include

srcs-y += $(COMMON_HAL)/hal_cfg.c
srcs-y += $(COMMON_HAL)/hal_rng.c
srcs-y += $(COMMON_HAL)/hal_jr.c
srcs-y += $(COMMON_HAL)/hal_ctrl.c
srcs-y += hal_clk.c
srcs-y += hal_ctrl.c
srcs-y += hal_jr.c

