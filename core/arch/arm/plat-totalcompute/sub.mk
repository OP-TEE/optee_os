global-incdirs-y += .
srcs-y += main.c
ifeq ($(CFG_CORE_FFA),y)
srcs-y += tc0_spmc_pm.c
endif
