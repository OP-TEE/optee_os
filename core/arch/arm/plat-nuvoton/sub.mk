global-incdirs-y += .
srcs-y += main.c
srcs-$(CFG_WITH_USER_TA) += vendor_props.c
ifeq ($(CFG_CORE_FFA),y)
ifeq ($(PLATFORM_FLAVOR_npcm845x),y)
srcs-y += npcm845x_spmc_pm.c

endif
endif
