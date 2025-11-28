$(call force,CFG_HWSUPP_MEM_PERM_WXN,y)
$(call force,CFG_HWSUPP_MEM_PERM_PXN,y)
$(call force,CFG_ENABLE_SCTLR_RR,n)
$(call force,CFG_ENABLE_SCTLR_Z,n)

# ARM debugger needs this
platform-cflags-debug-info = -gdwarf-2
platform-aflags-debug-info = -gdwarf-2

arm64-platform-cflags += -march=armv9.2-a
arm64-platform-aflags += -march=armv9.2-a
$(call force,CFG_ARM_GICV3,y)
