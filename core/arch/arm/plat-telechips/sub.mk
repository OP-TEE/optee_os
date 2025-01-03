global-incdirs-y += $(PLATFORM_FLAVOR)
global-incdirs-y += drivers/include

srcs-y += main.c
srcs-y += plat_tzc.c

subdirs-y += drivers
