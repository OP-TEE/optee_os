srcs-$(_CFG_CORE_LTC_MD5) += md5.c

ifeq ($(_CFG_CORE_LTC_SHA1),y)
srcs-y += sha1.c
endif

subdirs-y += helper
subdirs-y += sha2
