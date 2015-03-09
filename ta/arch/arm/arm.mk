ifeq ($(CFG_ARM64_user_ta),y)
user_ta-platform-cppflags += -DARM64=1
endif
ifeq ($(CFG_ARM32_user_ta),y)
user_ta-platform-cppflags += -DARM32=1
endif
