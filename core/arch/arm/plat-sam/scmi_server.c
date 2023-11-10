// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2019, STMicroelectronics
 * Copyright (c) 2021, Microchip
 */

#include <at91_clk.h>
#include <confine_array_index.h>
#include <drivers/scmi-msg.h>
#include <drivers/scmi.h>
#include <dt-bindings/clock/at91.h>
#include <initcall.h>
#include <tee_api_defines.h>

static_assert(SMT_BUF_SLOT_SIZE <= CFG_SCMI_SHMEM_SIZE);

register_phys_mem(MEM_AREA_IO_NSEC, CFG_SCMI_SHMEM_START, CFG_SCMI_SHMEM_SIZE);

struct channel_resources {
	struct scmi_msg_channel *channel;
};

static const struct channel_resources scmi_channel[] = {
	[0] = {
		.channel = &(struct scmi_msg_channel){
			.shm_addr = { .pa = CFG_SCMI_SHMEM_START },
			.shm_size = SMT_BUF_SLOT_SIZE,
		},
	},
};

static const struct channel_resources *find_resource(unsigned int channel_id)
{
	assert(channel_id < ARRAY_SIZE(scmi_channel));

	return scmi_channel + channel_id;
}

struct scmi_msg_channel *plat_scmi_get_channel(unsigned int channel_id)
{
	const size_t max_id = ARRAY_SIZE(scmi_channel);
	unsigned int confined_id = confine_array_index(channel_id, max_id);

	if (channel_id >= max_id)
		return NULL;

	return find_resource(confined_id)->channel;
}

static const char vendor[] = "Microchip";
static const char sub_vendor[] = "";

const char *plat_scmi_vendor_name(void)
{
	return vendor;
}

const char *plat_scmi_sub_vendor_name(void)
{
	return sub_vendor;
}

/* Currently supporting only SCMI Base protocol */
static const uint8_t plat_protocol_list[] = {
	SCMI_PROTOCOL_ID_CLOCK,
	0 /* Null termination */
};

size_t plat_scmi_protocol_count(void)
{
	return ARRAY_SIZE(plat_protocol_list) - 1;
}

const uint8_t *plat_scmi_protocol_list(unsigned int channel_id __unused)
{
	return plat_protocol_list;
}

struct sam_pmc_clk {
	unsigned int scmi_id;
	unsigned int pmc_type;
	unsigned int pmc_id;
};

#ifdef CFG_SAMA7G5
static const struct sam_pmc_clk pmc_clks[] = {
	{
		.scmi_id = AT91_SCMI_CLK_CORE_MCK,
		.pmc_type = PMC_TYPE_CORE,
		.pmc_id = PMC_MCK
	},
	{
		.scmi_id = AT91_SCMI_CLK_CORE_UTMI,
		.pmc_type = PMC_TYPE_CORE,
		.pmc_id = PMC_UTMI
	},
	{
		.scmi_id = AT91_SCMI_CLK_CORE_CPUPLLCK,
		.pmc_type = PMC_TYPE_CORE,
		.pmc_id = PMC_CPUPLL
	},
	{
		.scmi_id = AT91_SCMI_CLK_CORE_MAIN,
		.pmc_type = PMC_TYPE_CORE,
		.pmc_id = PMC_MAIN
	},
	{
		.scmi_id = AT91_SCMI_CLK_CORE_SYSPLLCK,
		.pmc_type = PMC_TYPE_CORE,
		.pmc_id = PMC_SYSPLL
	},

	{
		.scmi_id = AT91_SCMI_CLK_CORE_AUDIOPLLCK,
		.pmc_type = PMC_TYPE_CORE,
		.pmc_id = PMC_AUDIOPMCPLL
	},

	{
		.scmi_id = AT91_SCMI_CLK_CORE_MCK_PRES,
		.pmc_type = PMC_TYPE_CORE,
		.pmc_id = PMC_MCK_PRES
	},
	{
		.scmi_id = AT91_SCMI_CLK_CORE_DDRPLLCK,
		.pmc_type = PMC_TYPE_CORE,
		.pmc_id = PMC_DDRPLL
	},
	{
		.scmi_id = AT91_SCMI_CLK_CORE_IMGPLLCK,
		.pmc_type = PMC_TYPE_CORE,
		.pmc_id = PMC_IMGPLL
	},
	{
		.scmi_id = AT91_SCMI_CLK_CORE_ETHPLLCK,
		.pmc_type = PMC_TYPE_CORE,
		.pmc_id = PMC_ETHPLL
	},
	{
		.scmi_id = AT91_SCMI_CLK_UTMI1,
		.pmc_type = PMC_TYPE_CORE,
		.pmc_id = PMC_UTMI1
	},
	{
		.scmi_id = AT91_SCMI_CLK_UTMI2,
		.pmc_type = PMC_TYPE_CORE,
		.pmc_id = PMC_UTMI2
	},
	{
		.scmi_id = AT91_SCMI_CLK_UTMI3,
		.pmc_type = PMC_TYPE_CORE,
		.pmc_id = PMC_UTMI3
	},
	{
		.scmi_id = AT91_SCMI_CLK_SYSTEM_PCK0,
		.pmc_type = PMC_TYPE_SYSTEM,
		.pmc_id = 8
	},
	{
		.scmi_id = AT91_SCMI_CLK_SYSTEM_PCK1,
		.pmc_type = PMC_TYPE_SYSTEM,
		.pmc_id = 9
	},
	{
		.scmi_id = AT91_SCMI_CLK_SYSTEM_PCK2,
		.pmc_type = PMC_TYPE_SYSTEM,
		.pmc_id = 10
	},
	{
		.scmi_id = AT91_SCMI_CLK_SYSTEM_PCK3,
		.pmc_type = PMC_TYPE_SYSTEM,
		.pmc_id = 11
	},
	{
		.scmi_id = AT91_SCMI_CLK_SYSTEM_PCK4,
		.pmc_type = PMC_TYPE_SYSTEM,
		.pmc_id = 12
	},
	{
		.scmi_id = AT91_SCMI_CLK_SYSTEM_PCK5,
		.pmc_type = PMC_TYPE_SYSTEM,
		.pmc_id = 13
	},
	{
		.scmi_id = AT91_SCMI_CLK_SYSTEM_PCK6,
		.pmc_type = PMC_TYPE_SYSTEM,
		.pmc_id = 14
	},
	{
		.scmi_id = AT91_SCMI_CLK_SYSTEM_PCK7,
		.pmc_type = PMC_TYPE_SYSTEM,
		.pmc_id = 15
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_ASRC_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = ID_ASRC
	},
	{
		.scmi_id = AT91_SCMI_CLK_GCK_ASRC_GCLK,
		.pmc_type = PMC_TYPE_GCK,
		.pmc_id = ID_ASRC
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_CSI_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = ID_CSI
	},
	{
		.scmi_id = AT91_SCMI_CLK_GCK_CSI_GCLK,
		.pmc_type = PMC_TYPE_GCK,
		.pmc_id = ID_CSI
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_CSI2DC_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = ID_CSI2DC
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_MACB0_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = ID_GMAC0
	},
	{
		.scmi_id = AT91_SCMI_CLK_GCK_MACB0_GCLK,
		.pmc_type = PMC_TYPE_GCK,
		.pmc_id = ID_GMAC0
	},
	{
		.scmi_id = AT91_SCMI_CLK_GCK_MACB0_TSU,
		.pmc_type = PMC_TYPE_GCK,
		.pmc_id = ID_GMAC0_TSU
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_MACB1_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = ID_GMAC1
	},
	{
		.scmi_id = AT91_SCMI_CLK_GCK_MACB1_GCLK,
		.pmc_type = PMC_TYPE_GCK,
		.pmc_id = ID_GMAC1
	},
	{
		.scmi_id = AT91_SCMI_CLK_GCK_MACB1_TSU,
		.pmc_type = PMC_TYPE_GCK,
		.pmc_id = ID_GMAC1_TSU
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_TDES_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = ID_TDES
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_HSMC_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = ID_HSMC
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_PIOA_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = ID_PIOA
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_FLX0_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = ID_FLEXCOM0
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_FLX1_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = ID_FLEXCOM1
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_FLX2_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = ID_FLEXCOM2
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_FLX3_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = ID_FLEXCOM3
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_FLX4_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = ID_FLEXCOM4
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_FLX5_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = ID_FLEXCOM5
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_FLX6_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = ID_FLEXCOM6
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_FLX7_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = ID_FLEXCOM7
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_FLX8_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = ID_FLEXCOM8
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_FLX9_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = ID_FLEXCOM9
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_FLX10_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = ID_FLEXCOM10
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_FLX11_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = ID_FLEXCOM11
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_TCB0_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = ID_TC0_CHANNEL0
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_TCB1_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = ID_TC1_CHANNEL0
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_PWM_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = ID_PWM
	},
	{
		.scmi_id = AT91_SCMI_CLK_GCK_ADC_GCLK,
		.pmc_type = PMC_TYPE_GCK,
		.pmc_id = ID_ADC
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_UHPHS_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = ID_UHPHS
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_UDPHSA_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = ID_UDPHSA
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_UDPHSB_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = ID_UDPHSB
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_SSC0_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = ID_SSC0
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_SSC1_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = ID_SSC1
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_TRNG_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = ID_TRNG
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_PDMC0_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = ID_PDMC0
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_PDMC1_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = ID_PDMC1
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_SECURAM_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = ID_SECURAM
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_I2S0_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = ID_I2SMCC0
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_I2S1_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = ID_I2SMCC1
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_CAN0_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = ID_MCAN0
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_CAN1_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = ID_MCAN1
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_CAN2_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = ID_MCAN2
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_CAN3_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = ID_MCAN3
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_CAN4_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = ID_MCAN4
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_CAN5_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = ID_MCAN5
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_DMA0_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = ID_XDMAC0
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_DMA1_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = ID_XDMAC1
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_DMA2_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = ID_XDMAC2
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_SPDIFRX_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = ID_SPDIFRX
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_SPDIFTX_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = ID_SPDIFTX
	},
	{
		.scmi_id = AT91_SCMI_CLK_GCK_SPDIFRX_GCLK,
		.pmc_type = PMC_TYPE_GCK,
		.pmc_id = ID_SPDIFRX
	},
	{
		.scmi_id = AT91_SCMI_CLK_GCK_SPDIFTX_GCLK,
		.pmc_type = PMC_TYPE_GCK,
		.pmc_id = ID_SPDIFTX
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_AES_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = ID_AES
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_AESB_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = ID_TZAESBASC
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_SHA_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = ID_SHA
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_SDMMC0_HCLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = ID_SDMMC0
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_SDMMC1_HCLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = ID_SDMMC1
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_SDMMC2_HCLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = ID_SDMMC2
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_ISC_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = ID_ISC
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_QSPI0_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = ID_QSPI0
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_QSPI1_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = ID_QSPI1
	},
	{
		.scmi_id = AT91_SCMI_CLK_GCK_QSPI0_GCLK,
		.pmc_type = PMC_TYPE_GCK,
		.pmc_id = ID_QSPI0
	},
	{
		.scmi_id = AT91_SCMI_CLK_GCK_QSPI1_GCLK,
		.pmc_type = PMC_TYPE_GCK,
		.pmc_id = ID_QSPI1
	},
	{
		.scmi_id = AT91_SCMI_CLK_GCK_SDMMC0_GCLK,
		.pmc_type = PMC_TYPE_GCK,
		.pmc_id = ID_SDMMC0
	},
	{
		.scmi_id = AT91_SCMI_CLK_GCK_SDMMC1_GCLK,
		.pmc_type = PMC_TYPE_GCK,
		.pmc_id = ID_SDMMC1
	},
	{
		.scmi_id = AT91_SCMI_CLK_GCK_SDMMC2_GCLK,
		.pmc_type = PMC_TYPE_GCK,
		.pmc_id = ID_SDMMC2
	},
	{
		.scmi_id = AT91_SCMI_CLK_GCK_TCB0_GCLK,
		.pmc_type = PMC_TYPE_GCK,
		.pmc_id = ID_TC0_CHANNEL0
	},
	{
		.scmi_id = AT91_SCMI_CLK_GCK_TCB1_GCLK,
		.pmc_type = PMC_TYPE_GCK,
		.pmc_id = ID_TC1_CHANNEL0
	},
	{
		.scmi_id = AT91_SCMI_CLK_GCK_I2S0_GCLK,
		.pmc_type = PMC_TYPE_GCK,
		.pmc_id = ID_I2SMCC0
	},
	{
		.scmi_id = AT91_SCMI_CLK_GCK_I2S1_GCLK,
		.pmc_type = PMC_TYPE_GCK,
		.pmc_id = ID_I2SMCC1
	},
	{
		.scmi_id = AT91_SCMI_CLK_GCK_CAN0_GCLK,
		.pmc_type = PMC_TYPE_GCK,
		.pmc_id = ID_MCAN0
	},
	{
		.scmi_id = AT91_SCMI_CLK_GCK_CAN1_GCLK,
		.pmc_type = PMC_TYPE_GCK,
		.pmc_id = ID_MCAN1
	},
	{
		.scmi_id = AT91_SCMI_CLK_GCK_CAN2_GCLK,
		.pmc_type = PMC_TYPE_GCK,
		.pmc_id = ID_MCAN2
	},
	{
		.scmi_id = AT91_SCMI_CLK_GCK_CAN3_GCLK,
		.pmc_type = PMC_TYPE_GCK,
		.pmc_id = ID_MCAN3
	},
	{
		.scmi_id = AT91_SCMI_CLK_GCK_CAN4_GCLK,
		.pmc_type = PMC_TYPE_GCK,
		.pmc_id = ID_MCAN4
	},
	{
		.scmi_id = AT91_SCMI_CLK_GCK_CAN5_GCLK,
		.pmc_type = PMC_TYPE_GCK,
		.pmc_id = ID_MCAN5
	},
};
#else
static const struct sam_pmc_clk pmc_clks[] = {
	{
		.scmi_id = AT91_SCMI_CLK_CORE_MCK,
		.pmc_type = PMC_TYPE_CORE,
		.pmc_id = PMC_MCK
	},
	{
		.scmi_id = AT91_SCMI_CLK_CORE_UTMI,
		.pmc_type = PMC_TYPE_CORE,
		.pmc_id = PMC_UTMI
	},
	{
		.scmi_id = AT91_SCMI_CLK_CORE_MAIN,
		.pmc_type = PMC_TYPE_CORE,
		.pmc_id = PMC_MAIN
	},
	{
		.scmi_id = AT91_SCMI_CLK_CORE_MCK2,
		.pmc_type = PMC_TYPE_CORE,
		.pmc_id = PMC_MCK2
	},
	{
		.scmi_id = AT91_SCMI_CLK_CORE_I2S0_MUX,
		.pmc_type = PMC_TYPE_CORE,
		.pmc_id = PMC_I2S0_MUX
	},
	{
		.scmi_id = AT91_SCMI_CLK_CORE_I2S1_MUX,
		.pmc_type = PMC_TYPE_CORE,
		.pmc_id = PMC_I2S1_MUX
	},
	{
		.scmi_id = AT91_SCMI_CLK_CORE_PLLACK,
		.pmc_type = PMC_TYPE_CORE,
		.pmc_id = PMC_PLLACK
	},
	{
		.scmi_id = AT91_SCMI_CLK_CORE_AUDIOPLLCK,
		.pmc_type = PMC_TYPE_CORE,
		.pmc_id = PMC_AUDIOPLLCK
	},
	{
		.scmi_id = AT91_SCMI_CLK_CORE_MCK_PRES,
		.pmc_type = PMC_TYPE_CORE,
		.pmc_id = PMC_MCK_PRES
	},
	{
		.scmi_id = AT91_SCMI_CLK_SYSTEM_DDRCK,
		.pmc_type = PMC_TYPE_SYSTEM,
		.pmc_id = 2
	},
	{
		.scmi_id = AT91_SCMI_CLK_SYSTEM_LCDCK,
		.pmc_type = PMC_TYPE_SYSTEM,
		.pmc_id = 3
	},
	{
		.scmi_id = AT91_SCMI_CLK_SYSTEM_UHPCK,
		.pmc_type = PMC_TYPE_SYSTEM,
		.pmc_id = 6
	},
	{
		.scmi_id = AT91_SCMI_CLK_SYSTEM_UDPCK,
		.pmc_type = PMC_TYPE_SYSTEM,
		.pmc_id = 7
	},
	{
		.scmi_id = AT91_SCMI_CLK_SYSTEM_PCK0,
		.pmc_type = PMC_TYPE_SYSTEM,
		.pmc_id = 8
	},
	{
		.scmi_id = AT91_SCMI_CLK_SYSTEM_PCK1,
		.pmc_type = PMC_TYPE_SYSTEM,
		.pmc_id = 9
	},
	{
		.scmi_id = AT91_SCMI_CLK_SYSTEM_PCK2,
		.pmc_type = PMC_TYPE_SYSTEM,
		.pmc_id = 10
	},
	{
		.scmi_id = AT91_SCMI_CLK_SYSTEM_ISCCK,
		.pmc_type = PMC_TYPE_SYSTEM,
		.pmc_id = 18
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_MACB0_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = 5
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_TDES_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = 11
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_MATRIX1_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = 14
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_HSMC_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = 17
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_PIOA_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = 18
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_FLX0_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = 19
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_FLX1_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = 20
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_FLX2_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = 21
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_FLX3_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = 22
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_FLX4_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = 23
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_UART0_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = 24
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_UART1_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = 25
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_UART2_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = 26
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_UART3_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = 27
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_UART4_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = 28
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_TWI0_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = 29
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_TWI1_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = 30
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_SPI0_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = 33
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_SPI1_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = 34
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_TCB0_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = 35
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_TCB1_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = 36
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_PWM_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = 38
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_ADC_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = 40
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_UHPHS_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = 41
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_UDPHS_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = 42
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_SSC0_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = 43
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_SSC1_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = 44
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_TRNG_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = 47
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_PDMIC_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = 48
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_SECURAM_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = 51
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_I2S0_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = 54
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_I2S1_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = 55
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_CAN0_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = 56
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_CAN1_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = 57
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_PTC_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = 58
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_CLASSD_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = 59
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_DMA0_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = 6
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_DMA1_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = 7
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_AES_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = 9
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_AESB_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = 10
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_SHA_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = 12
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_MPDDR_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = 13
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_MATRIX0_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = 15
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_SDMMC0_HCLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = 31
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_SDMMC1_HCLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = 32
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_LCDC_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = 45
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_ISC_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = 46
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_QSPI0_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = 52
	},
	{
		.scmi_id = AT91_SCMI_CLK_PERIPH_QSPI1_CLK,
		.pmc_type = PMC_TYPE_PERIPHERAL,
		.pmc_id = 53
	},
	{
		.scmi_id = AT91_SCMI_CLK_GCK_SDMMC0_GCLK,
		.pmc_type = PMC_TYPE_GCK,
		.pmc_id = 31
	},
	{
		.scmi_id = AT91_SCMI_CLK_GCK_SDMMC1_GCLK,
		.pmc_type = PMC_TYPE_GCK,
		.pmc_id = 32
	},
	{
		.scmi_id = AT91_SCMI_CLK_GCK_TCB0_GCLK,
		.pmc_type = PMC_TYPE_GCK,
		.pmc_id = 35
	},
	{
		.scmi_id = AT91_SCMI_CLK_GCK_TCB1_GCLK,
		.pmc_type = PMC_TYPE_GCK,
		.pmc_id = 36
	},
	{
		.scmi_id = AT91_SCMI_CLK_GCK_PWM_GCLK,
		.pmc_type = PMC_TYPE_GCK,
		.pmc_id = 38
	},
	{
		.scmi_id = AT91_SCMI_CLK_GCK_ISC_GCLK,
		.pmc_type = PMC_TYPE_GCK,
		.pmc_id = 46
	},
	{
		.scmi_id = AT91_SCMI_CLK_GCK_PDMIC_GCLK,
		.pmc_type = PMC_TYPE_GCK,
		.pmc_id = 48
	},
	{
		.scmi_id = AT91_SCMI_CLK_GCK_I2S0_GCLK,
		.pmc_type = PMC_TYPE_GCK,
		.pmc_id = 54
	},
	{
		.scmi_id = AT91_SCMI_CLK_GCK_I2S1_GCLK,
		.pmc_type = PMC_TYPE_GCK,
		.pmc_id = 55
	},
	{
		.scmi_id = AT91_SCMI_CLK_GCK_CAN0_GCLK,
		.pmc_type = PMC_TYPE_GCK,
		.pmc_id = 56
	},
	{
		.scmi_id = AT91_SCMI_CLK_GCK_CAN1_GCLK,
		.pmc_type = PMC_TYPE_GCK,
		.pmc_id = 57
	},
	{
		.scmi_id = AT91_SCMI_CLK_GCK_CLASSD_GCLK,
		.pmc_type = PMC_TYPE_GCK,
		.pmc_id = 59
	},
	{
		.scmi_id = AT91_SCMI_CLK_PROG_PROG0,
		.pmc_type = PMC_TYPE_PROGRAMMABLE,
		.pmc_id = 0
	},
	{
		.scmi_id = AT91_SCMI_CLK_PROG_PROG1,
		.pmc_type = PMC_TYPE_PROGRAMMABLE,
		.pmc_id = 1
	},
	{
		.scmi_id = AT91_SCMI_CLK_PROG_PROG2,
		.pmc_type = PMC_TYPE_PROGRAMMABLE,
		.pmc_id = 2
	},
};
#endif

static TEE_Result sam_init_scmi_clk(void)
{
	unsigned int i = 0;
	struct clk *clk = NULL;
	TEE_Result res = TEE_ERROR_GENERIC;
	const struct sam_pmc_clk *pmc_clk = NULL;

	for (i = 0; i < ARRAY_SIZE(pmc_clks); i++) {
		pmc_clk = &pmc_clks[i];
		res = at91_pmc_clk_get(pmc_clk->pmc_type, pmc_clk->pmc_id,
				       &clk);
		if (res) {
			EMSG("Failed to get PMC clock type %u, id %u",
			     pmc_clk->pmc_type, pmc_clk->pmc_id);
			return res;
		}
		res = scmi_clk_add(clk, 0, pmc_clk->scmi_id);
		if (res) {
			EMSG("Failed to add PMC SCMI clock id %u",
			     pmc_clk->scmi_id);
			return res;
		}
	}

	clk = at91_sckc_clk_get();
	if (!clk)
		return TEE_ERROR_GENERIC;

	res = scmi_clk_add(clk, 0, AT91_SCMI_CLK_SCKC_SLOWCK_32K);
	if (res) {
		EMSG("Failed to add slow clock to SCMI clocks");
		return res;
	}

	return TEE_SUCCESS;
}

/*
 * Initialize platform SCMI resources
 */
static TEE_Result sam_init_scmi_server(void)
{
	size_t i = 0;

	for (i = 0; i < ARRAY_SIZE(scmi_channel); i++) {
		const struct channel_resources *res = scmi_channel + i;
		struct scmi_msg_channel *chan = res->channel;

		/* Enforce non-secure shm mapped as device memory */
		chan->shm_addr.va = (vaddr_t)phys_to_virt(chan->shm_addr.pa,
							  MEM_AREA_IO_NSEC, 1);
		assert(chan->shm_addr.va);

		scmi_smt_init_agent_channel(chan);
	}

	return sam_init_scmi_clk();
}

driver_init_late(sam_init_scmi_server);
