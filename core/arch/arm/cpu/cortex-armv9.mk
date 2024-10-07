$(call force,CFG_HWSUPP_MEM_PERM_WXN,y)
$(call force,CFG_HWSUPP_MEM_PERM_PXN,y)
$(call force,CFG_ENABLE_SCTLR_RR,n)
$(call force,CFG_ENABLE_SCTLR_Z,n)

arm32-platform-cflags 	+= -mcpu=$(arm32-platform-cpuarch)
arm32-platform-aflags 	+= -mcpu=$(arm32-platform-cpuarch)
arm32-platform-cxxflags	+= -mcpu=$(arm32-platform-cpuarch)

arm64-platform-cflags 	+= -mcpu=$(arm64-platform-cpuarch)
arm64-platform-aflags 	+= -mcpu=$(arm64-platform-cpuarch)
arm64-platform-cxxflags	+= -mcpu=$(arm64-platform-cpuarch)

platform-flavor-armv9 	:= 1
