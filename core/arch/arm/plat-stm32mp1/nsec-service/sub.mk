global-incdirs-y += .

srcs-y += stm32mp1_svc_setup.c
srcs-$(CFG_STM32_BSEC_SIP) += bsec_svc.c
