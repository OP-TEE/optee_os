ifeq ($(CFG_ARM64_core),y)
core-platform-cppflags += -DARM64=1
endif
ifeq ($(CFG_ARM32_core),y)
core-platform-cppflags += -DARM32=1
endif
