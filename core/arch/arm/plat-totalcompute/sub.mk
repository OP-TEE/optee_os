global-incdirs-y += .
srcs-y += main.c
ifeq ($(CFG_CORE_FFA),y)
srcs-y += tc_spmc_pm.c
endif
