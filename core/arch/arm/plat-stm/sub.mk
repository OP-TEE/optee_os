global-incdirs-y += .

srcs-y += tee_common_otp.c
cflags-tee_common_otp.c-y += -Wno-unused-parameter

srcs-y += core_bootcfg.c
srcs-$(platform_flavor_orly2) += core_chip_orly2.c
srcs-$(platform_flavor_cannes) += core_chip_cannes.c
srcs-y += rng_support.c

srcs-y += asc.S
srcs-y += tz_a9init.S
srcs-y += main.c
srcs-y += cache_maintenance.c

srcs-y += tz_sinit.S
aflags-tz_sinit.S-y += \
	-Xassembler --defsym \
	-Xassembler STM_SECONDARY_STARTUP=$(SECONDARY_STARTUP_PHYS) \
	-Xassembler --defsym \
	-Xassembler STEXT=$(PRIMARY_STARTUP_PHYS)
