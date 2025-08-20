global-incdirs-y += .
srcs-y += main.c

ifeq ($(PLATFORM_FLAVOR),rd1ae)
srcs-y	+= rd1ae_core_pos.S
endif
