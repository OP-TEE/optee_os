global-incdirs-y += .

srcs-y += at91_sckc.c at91_main.c at91_pmc.c
srcs-y += at91_utmi.c at91_master.c
srcs-y += at91_programmable.c at91_system.c at91_peripheral.c
srcs-y += at91_generated.c

srcs-$(CFG_SAMA5D2) += at91_pll.c at91_plldiv.c
srcs-$(CFG_SAMA5D2) += at91_h32mx.c at91_usb.c
srcs-$(CFG_SAMA5D2) += at91_i2s_mux.c at91_audio_pll.c
srcs-$(CFG_SAMA5D2) += sama5d2_clk.c

srcs-$(CFG_SAMA7G5) += clk-sam9x60-pll.c phy-sama7-utmi-clk.c sama7g5_clk.c
