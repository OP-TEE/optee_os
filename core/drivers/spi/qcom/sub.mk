ifeq ($(CFG_QCOM_GENI_SPI),y)
srcs-y += qcom_geni_spi.c
srcs-$(CFG_QUP_SPI_TEST) += qcom_geni_spi_test.c
subdirs-y += platform
endif
