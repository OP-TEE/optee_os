cflags-y += -Wno-unused-parameter

ifneq ($(_CFG_CORE_LTC_AES_ACCEL),y)
srcs-$(_CFG_CORE_LTC_AES_DESC) += aes.c
endif
