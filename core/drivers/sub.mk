ifeq ($(CFG_PL061),y)
$(call force,CFG_GPIO,y,required by CFG_PL061)
endif

srcs-$(CFG_CDNS_UART) += cdns_uart.c
srcs-$(CFG_PL011) += pl011.c
srcs-$(CFG_GIC) += gic.c
srcs-$(CFG_GPIO) += gpio.c
srcs-$(CFG_PL061) += pl061_gpio.c
srcs-$(CFG_SUNXI_UART) += sunxi_uart.c
srcs-$(CFG_8250_UART) += serial8250_uart.c
srcs-$(CFG_16550_UART) += ns16550.c
srcs-$(CFG_IMX_UART) += imx_uart.c
srcs-$(CFG_SPRD_UART) += sprd_uart.c
