ifeq ($(CFG_CORE_FFA),y)
ifeq ($(PLATFORM_FLAVOR_npcm845x),y)
srcs-y += npcm845x_spmc_pm.c
endif
endif