$(call force,CFG_ARM32_core,y)
$(call force,CFG_ARM64_core,n)
$(call force,CFG_HWSUPP_MEM_PERM_WXN,y)
$(call force,CFG_HWSUPP_MEM_PERM_PXN,y)
arm32-platform-cpuarch 	:= cortex-a15
arm32-platform-cflags 	+= -mcpu=$(arm32-platform-cpuarch)
arm32-platform-aflags 	+= -mcpu=$(arm32-platform-cpuarch)
arm32-platform-cxxflags	+= -mcpu=$(arm32-platform-cpuarch)
# Program flow prediction may need manual enablement
CFG_ENABLE_SCTLR_Z ?= y
