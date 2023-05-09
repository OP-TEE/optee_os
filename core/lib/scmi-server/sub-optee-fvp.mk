incdirs_ext-y += $(scpfw-path)/product/optee-fvp/fw
incdirs_ext-y += $(scpfw-path)/product/optee-fvp/include

srcs-y += $(scpfw-path)/product/optee-fvp/fw/config_clock.c
srcs-y += $(scpfw-path)/product/optee-fvp/fw/config_dvfs.c
srcs-y += $(scpfw-path)/product/optee-fvp/fw/config_mbx_smt.c
srcs-y += $(scpfw-path)/product/optee-fvp/fw/config_mock_clock.c
srcs-y += $(scpfw-path)/product/optee-fvp/fw/config_mock_ppu.c
srcs-y += $(scpfw-path)/product/optee-fvp/fw/config_mock_psu.c
srcs-y += $(scpfw-path)/product/optee-fvp/fw/config_power_domain.c
srcs-y += $(scpfw-path)/product/optee-fvp/fw/config_psu.c
srcs-y += $(scpfw-path)/product/optee-fvp/fw/config_scmi.c
srcs-y += $(scpfw-path)/product/optee-fvp/fw/config_scmi_clock.c
srcs-y += $(scpfw-path)/product/optee-fvp/fw/config_scmi_perf.c
srcs-y += $(scpfw-path)/product/optee-fvp/fw/config_scmi_power_domain.c
srcs-y += $(scpfw-path)/product/optee-fvp/fw/config_sensor.c
srcs-y += $(scpfw-path)/product/optee-fvp/fw/config_vpll.c
