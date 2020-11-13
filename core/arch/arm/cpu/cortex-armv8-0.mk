$(call force,CFG_HWSUPP_MEM_PERM_WXN,y)
$(call force,CFG_HWSUPP_MEM_PERM_PXN,y)
$(call force,CFG_ENABLE_SCTLR_RR,n)
$(call force,CFG_ENABLE_SCTLR_Z,n)
# cortex-a53 and cortex-a57 complies on arm32 architectures
arm32-platform-cpuarch 	:= cortex-a53
arm32-platform-cflags 	+= -mcpu=$(arm32-platform-cpuarch)
arm32-platform-aflags 	+= -mcpu=$(arm32-platform-cpuarch)
arm32-platform-cxxflags	+= -mcpu=$(arm32-platform-cpuarch)
platform-flavor-armv8 := 1
