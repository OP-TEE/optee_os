srcs-$(_CFG_CORE_LTC_MD5) += md5.c

ifeq ($(_CFG_CORE_LTC_SHA1),y)
ifneq ($(_CFG_CORE_LTC_SHA1_ACCEL),y)
srcs-y += sha1.c
endif
endif

subdirs-y += helper
subdirs-y += sha2
