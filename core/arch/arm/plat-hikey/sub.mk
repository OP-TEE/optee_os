global-incdirs-y += .
srcs-y += main.c
ifeq ($(PLATFORM_FLAVOR),hikey)
srcs-$(CFG_SPI_TEST) += spi_test.c
endif
