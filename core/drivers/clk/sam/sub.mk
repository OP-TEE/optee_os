global-incdirs-y += .

at91-common = at91_sckc.c at91_main.c at91_pmc.c at91_pll.c at91_plldiv.c
at91-common += at91_utmi.c at91_master.c at91_h32mx.c at91_usb.c
at91-common += at91_programmable.c at91_system.c at91_peripheral.c
at91-common += at91_generated.c at91_i2s_mux.c at91_audio_pll.c

srcs-$(CFG_DRIVERS_SAMA5D2_CLK) += $(at91-common) sama5d2_clk.c
