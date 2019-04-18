/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2017-2018 NXP
 *
 */
#ifndef __MX6_CCM_REGS_H__
#define __MX6_CCM_REGS_H__

#define CCM_CCR			0x0000
#define CCM_CCDR		0x0004
#define CCM_CSR			0x0008
#define CCM_CCSR		0x000C
#define CCM_CACRR		0x0010
#define CCM_CBCDR		0x0014
#define CCM_CBCMR		0x0018
#define CCM_CSCMR1		0x001C
#define CCM_CSCMR2		0x0020
#define CCM_CSCDR1		0x0024
#define CCM_CS1CDR		0x0028
#define CCM_CS2CDR		0x002C
#define CCM_CDCDR		0x0030
#define CCM_CHSCCDR		0x0034
#define CCM_CSCDR2		0x0038
#define CCM_CSCDR3		0x003C
#define CCM_CSCDR4		0x0040
#define CCM_CWDR		0x0044
#define CCM_CDHIPR		0x0048
#define CCM_CDCR		0x004C
#define CCM_CTOR		0x0050
#define CCM_CLPCR		0x0054
#define CCM_CISR		0x0058
#define CCM_CIMR		0x005C
#define CCM_CCOSR		0x0060
#define CCM_CGPR		0x0064
#define CCM_CCGR0		0x0068
#define CCM_CCGR1		0x006C
#define CCM_CCGR2		0x0070
#define CCM_CCGR3		0x0074
#define CCM_CCGR4		0x0078
#define CCM_CCGR5		0x007C
#define CCM_CCGR6		0x0080
#define CCM_CCGR7		0x0084
#define CCM_CMEOR		0x0088

#define CCM_ANALOG_PLL_SYS			0x4000
#define CCM_ANALOG_PLL_SYS_SET			0x4004
#define CCM_ANALOG_PLL_SYS_CLR			0x4008
#define CCM_ANALOG_PLL_SYS_TOG			0x400C
#define CCM_ANALOG_USB1_PLL_480_CTRL		0x4010
#define CCM_ANALOG_USB1_PLL_480_CTRL_SET	0x4014
#define CCM_ANALOG_USB1_PLL_480_CTRL_CLR	0x4018
#define CCM_ANALOG_USB1_PLL_480_CTRL_TOG	0x401C

#define CCM_ANALOG_PLL_528			0x4030
#define CCM_ANALOG_PLL_528_SET			0x4034
#define CCM_ANALOG_PLL_528_CLR			0x4038
#define CCM_ANALOG_PLL_528_TOG			0x403C
#define CCM_ANALOG_PLL_528_SS			0x4040
#define CCM_ANALOG_PLL_528_NUM			0x4050
#define CCM_ANALOG_PLL_528_DENOM		0x4060
#define CCM_ANALOG_PLL_AUDIO			0x4070
#define CCM_ANALOG_PLL_AUDIO_SET		0x4074
#define CCM_ANALOG_PLL_AUDIO_CLR		0x4078
#define CCM_ANALOG_PLL_AUDIO_TOG		0x407C
#define CCM_ANALOG_PLL_AUDIO_NUM		0x4080
#define CCM_ANALOG_PLL_AUDIO_DENOM		0x4090
#define CCM_ANALOG_PLL_VIDEO			0x40A0
#define CCM_ANALOG_PLL_VIDEO_SET		0x40A4
#define CCM_ANALOG_PLL_VIDEO_CLR		0x40A8
#define CCM_ANALOG_PLL_VIDEO_TOG		0x40AC
#define CCM_ANALOG_PLL_VIDEO_NUM		0x40B0
#define CCM_ANALOG_PLL_VEDIO_DENON		0x40C0
#define CCM_ANALOG_PLL_ENET			0x40E0
#define CCM_ANALOG_PLL_ENET_SET			0x40E4
#define CCM_ANALOG_PLL_ENET_CLR			0x40E8
#define CCM_ANALOG_PLL_ENET_TOG			0x40EC
#define CCM_ANALOG_PFD_480			0x40F0
#define CCM_ANALOG_PFD_480_SET			0x40F4
#define CCM_ANALOG_PFD_480_CLR			0x40F8
#define CCM_ANALOG_PFD_480_TOG			0x40FC
#define CCM_ANALOG_PFD_528			0x4100
#define CCM_ANALOG_PFD_528_SET			0x4104
#define CCM_ANALOG_PFD_528_CLR			0x4108
#define CCM_ANALOG_PFD_528_TOG			0x410C


/* Define the bits in register CCR */
#define BS_CCM_CCR_RBC_EN		27
#define BM_CCM_CCR_RBC_EN		BIT32(BS_CCM_CCR_RBC_EN)
#define BS_CCM_CCR_REG_BYPASS_COUNT	21
#define BM_CCM_CCR_REG_BYPASS_COUNT	\
				SHIFT_U32(0x3F, BS_CCM_CCR_REG_BYPASS_COUNT)
#define BS_CCM_CCR_WB_COUNT		16
#define BM_CCM_CCR_WB_COUNT		SHIFT_U32(0x7, BS_CCM_CCR_WB_COUNT)
#define BS_CCM_CCR_OSCNT		0
#define BM_CCM_CCR_OSCNT		SHIFT_U32(0xFF, BS_CCM_CCR_OSCNT)
#define CCM_CCR_COSC_EN			SHIFT_U32((1 << 12), BS_CCM_CCR_OSCNT)

/* Define the bits in register CCDR */
#define BS_CCM_CCDR_MMDC_CH1_HS_MASK	16
#define BM_CCM_CCDR_MMDC_CH1_HS_MASK	BIT32(BS_CCM_CCDR_MMDC_CH1_HS_MASK)
#define BS_CCM_CCDR_MMDC_CH0_HS_MASK	17
#define BM_CCM_CCDR_MMDC_CH0_HS_MASK	BIT32(BS_CCM_CCDR_MMDC_CH0_HS_MASK)

/* Define the bits in register CSR */
#define BS_CCM_CSR_COSC_READY		5
#define BM_CCM_CSR_COSC_READY		BIT32(BS_CCM_CSR_COSC_READY)
#define BS_CCM_CSR_REF_EN_B		0
#define BM_CCM_CSR_REF_EN_B		BIT32(BS_CCM_CSR_REF_EN_B)

/* Define the bits in register CCSR */
#define BS_CCM_CCSR_PDF_540M_AUTO_DIS	15
#define BM_CCM_CCSR_PDF_540M_AUTO_DIS	BIT32(BS_CCM_CCSR_PDF_540M_AUTO_DIS)
#define BS_CCM_CCSR_PDF_720M_AUTO_DIS	14
#define BM_CCM_CCSR_PDF_720M_AUTO_DIS	BIT32(BS_CCM_CCSR_PDF_720M_AUTO_DIS)
#define BS_CCM_CCSR_PDF_454M_AUTO_DIS	13
#define BM_CCM_CCSR_PDF_454M_AUTO_DIS	BIT32(BS_CCM_CCSR_PDF_454M_AUTO_DIS)
#define BS_CCM_CCSR_PDF_508M_AUTO_DIS	12
#define BM_CCM_CCSR_PDF_508M_AUTO_DIS	BIT32(BS_CCM_CCSR_PDF_508M_AUTO_DIS)
#define BS_CCM_CCSR_PDF_594M_AUTO_DIS	11
#define BM_CCM_CCSR_PDF_594M_AUTO_DIS	BIT32(BS_CCM_CCSR_PDF_594M_AUTO_DIS)
#define BS_CCM_CCSR_PDF_352M_AUTO_DIS	10
#define BM_CCM_CCSR_PDF_352M_AUTO_DIS	BIT32(BS_CCM_CCSR_PDF_352M_AUTO_DIS)
#define BS_CCM_CCSR_PDF_400M_AUTO_DIS	9
#define BM_CCM_CCSR_PDF_400M_AUTO_DIS	BIT32(BS_CCM_CCSR_PDF_400M_AUTO_DIS)
#define BS_CCM_CCSR_STEP_SEL		8
#define BM_CCM_CCSR_STEP_SEL		BIT32(BS_CCM_CCSR_STEP_SEL)
#define BS_CCM_CCSR_PLL1_SW_CLK_SEL	2
#define BM_CCM_CCSR_PLL1_SW_CLK_SEL	BIT32(BS_CCM_CCSR_PLL1_SW_CLK_SEL)
#define BS_CCM_CCSR_PLL2_SW_CLK_SEL	1
#define BM_CCM_CCSR_PLL2_SW_CLK_SEL	BIT32(BS_CCM_CCSR_PLL2_SW_CLK_SEL)
#define BS_CCM_CCSR_PLL3_SW_CLK_SEL	0
#define BM_CCM_CCSR_PLL3_SW_CLK_SEL	BIT32(BS_CCM_CCSR_PLL3_SW_CLK_SEL)

/* Define the bits in register CACRR */
#define BS_CCM_CACRR_ARM_PODF		0
#define BM_CCM_CACRR_ARM_PODF		SHIFT_U32(0x7, BS_CCM_CACRR_ARM_PODF)

/* Define the bits in register CBCDR */
#define BS_CCM_CBCDR_PERIPH_CLK2_PODF	27
#define BM_CCM_CBCDR_PERIPH_CLK2_PODF	\
				SHIFT_U32(0x7, BS_CCM_CBCDR_PERIPH_CLK2_PODF)
#define BS_CCM_CBCDR_PERIPH2_CLK2_SEL	26
#define BM_CCM_CBCDR_PERIPH2_CLK2_SEL	BIT32(BS_CCM_CBCDR_PERIPH2_CLK2_SEL)
#define BS_CCM_CBCDR_PERIPH_CLK_SEL	25
#define BM_CCM_CBCDR_PERIPH_CLK_SEL	BIT32(BS_CCM_CBCDR_PERIPH_CLK_SEL)
#define BS_CCM_CBCDR_MMDC_CH0_PODF	19
#define BM_CCM_CBCDR_MMDC_CH0_PODF	\
				SHIFT_U32(0x7, BS_CCM_CBCDR_MMDC_CH0_PODF)
#define BS_CCM_CBCDR_AXI_PODF		16
#define BM_CCM_CBCDR_AXI_PODF		SHIFT_U32(0x7, BS_CCM_CBCDR_AXI_PODF)
#define BS_CCM_CBCDR_AHB_PODF		10
#define BM_CCM_CBCDR_AHB_PODF		SHIFT_U32(0x7, BS_CCM_CBCDR_AHB_PODF)
#define BS_CCM_CBCDR_IPG_PODF		8
#define BM_CCM_CBCDR_IPG_PODF		SHIFT_U32(0x3, BS_CCM_CBCDR_IPG_PODF)
#define BS_CCM_CBCDR_AXI_ALT_SEL	7
#define BM_CCM_CBCDR_AXI_ALT_SEL	BIT32(BS_CCM_CBCDR_AXI_ALT_SEL)
#define BS_CCM_CBCDR_AXI_SEL		6
#define BM_CCM_CBCDR_AXI_SEL		BIT32(BS_CCM_CBCDR_AXI_SEL)
#define BS_CCM_CBCDR_MMDC_CH1_PODF	3
#define BM_CCM_CBCDR_MMDC_CH1_PODF	\
				SHIFT_U32(0x7, BS_CCM_CBCDR_MMDC_CH1_PODF)
#define BS_CCM_CBCDR_PERIPH2_CLK2_PODF	0
#define BM_CCM_CBCDR_PERIPH2_CLK2_PODF	\
				SHIFT_U32(0x7, BS_CCM_CBCDR_PERIPH2_CLK2_PODF)

/* Define the bits in register CBCMR */
#define BS_CCM_CBCMR_GPU3D_SHADER_PODF	29
#define BM_CCM_CBCMR_GPU3D_SHADER_PODF	\
				SHIFT_U32(0x7, BS_CCM_CBCMR_GPU3D_SHADER_PODF)
#define BS_CCM_CBCMR_GPU3D_CORE_PODF	26
#define BM_CCM_CBCMR_GPU3D_CORE_PODF	\
				SHIFT_U32(0x7, BS_CCM_CBCMR_GPU3D_CORE_PODF)
#define BS_CCM_CBCMR_GPU2D_CORE_PODF	23
#define BM_CCM_CBCMR_GPU2D_CORE_PODF	\
				SHIFT_U32(0x7, BS_CCM_CBCMR_GPU2D_CORE_PODF)
#define BS_CCM_CBCMR_PRE_PERIPH2_CLK_SEL	21
#define BM_CCM_CBCMR_PRE_PERIPH2_CLK_SEL	\
			SHIFT_U32(0x3, BS_CCM_CBCMR_PRE_PERIPH2_CLK_SEL)
#define BS_CCM_CBCMR_PRE_PERIPH2_CLK2_SEL	20
#define BM_CCM_CBCMR_PRE_PERIPH2_CLK2_SEL	\
			BIT32(BS_CCM_CBCMR_PRE_PERIPH2_CLK2_SEL)
#define BS_CCM_CBCMR_PRE_PERIPH_CLK_SEL		18
#define BM_CCM_CBCMR_PRE_PERIPH_CLK_SEL		\
			SHIFT_U32(0x3, BS_CCM_CBCMR_PRE_PERIPH_CLK_SEL)
#define BS_CCM_CBCMR_GPU2D_CLK_SEL	16
#define BM_CCM_CBCMR_GPU2D_CLK_SEL	\
				SHIFT_U32(0x3, BS_CCM_CBCMR_GPU2D_CLK_SEL)
#define BS_CCM_CBCMR_VPU_AXI_CLK_SEL	14
#define BM_CCM_CBCMR_VPU_AXI_CLK_SEL	\
				SHIFT_U32(0x3, BS_CCM_CBCMR_VPU_AXI_CLK_SEL)
#define BS_CCM_CBCMR_PERIPH_CLK2_SEL	12
#define BM_CCM_CBCMR_PERIPH_CLK2_SEL	\
				SHIFT_U32(0x3, BS_CCM_CBCMR_PERIPH_CLK2_SEL)
#define BS_CCM_CBCMR_VDOAXI_CLK_SEL	11
#define BM_CCM_CBCMR_VDOAXI_CLK_SEL	BIT32(BS_CCM_CBCMR_VDOAXI_CLK_SEL)
#define BS_CCM_CBCMR_PCIE_AXI_CLK_SEL	10
#define BM_CCM_CBCMR_PCIE_AXI_CLK_SEL	BIT32(BS_CCM_CBCMR_PCIE_AXI_CLK_SE)
#define BS_CCM_CBCMR_GPU3D_SHADER_CLK_SEL	8
#define BM_CCM_CBCMR_GPU3D_SHADER_CLK_SEL	\
			SHIFT_U32(0x3, BS_CCM_CBCMR_GPU3D_SHADER_CLK_SEL)
#define BS_CCM_CBCMR_GPU3D_CORE_CLK_SEL		4
#define BM_CCM_CBCMR_GPU3D_CORE_CLK_SEL		\
			SHIFT_U32(0x3, BS_CCM_CBCMR_GPU3D_CORE_CLK_SEL)
#define BS_CCM_CBCMR_GPU3D_AXI_CLK_SEL		1
#define BM_CCM_CBCMR_GPU3D_AXI_CLK_SEL		\
			BIT32(BS_CCM_CBCMR_GPU3D_AXI_CLK_SEL)
#define BS_CCM_CBCMR_GPU2D_AXI_CLK_SEL		0
#define BM_CCM_CBCMR_GPU2D_AXI_CLK_SEL		\
			BIT32(BS_CCM_CBCMR_GPU2D_AXI_CLK_SELx0)

/* Define the bits in register CSCMR1 */
#define BS_CCM_CSCMR1_ACLK_EMI_SLOW	29
#define BM_CCM_CSCMR1_ACLK_EMI_SLOW	\
				SHIFT_U32(0x3, BS_CCM_CSCMR1_ACLK_EMI_SLOW)
#define BS_CCM_CSCMR1_ACLK_EMI		27
#define BM_CCM_CSCMR1_ACLK_EMI		SHIFT_U32(0x3, BS_CCM_CSCMR1_ACLK_EMI)
#define BS_CCM_CSCMR1_ACLK_EMI_SLOW_PODF	23
#define BM_CCM_CSCMR1_ACLK_EMI_SLOW_PODF	\
			SHIFT_U32(0x7, BS_CCM_CSCMR1_ACLK_EMI_SLOW_PODF)
#define BS_CCM_CSCMR1_ACLK_EMI_PODF		20
#define BM_CCM_CSCMR1_ACLK_EMI_PODF		\
			SHIFT_U32(0x7, BS_CCM_CSCMR1_ACLK_EMI_PODF)
#define BS_CCM_CSCMR1_USDHC4_CLK_SEL		19
#define BM_CCM_CSCMR1_USDHC4_CLK_SEL		\
			BIT32(BS_CCM_CSCMR1_USDHC4_CLK_SEL)
#define BS_CCM_CSCMR1_USDHC3_CLK_SEL		18
#define BM_CCM_CSCMR1_USDHC3_CLK_SEL		\
			BIT32(BS_CCM_CSCMR1_USDHC3_CLK_SEL)
#define BS_CCM_CSCMR1_USDHC2_CLK_SEL		17
#define BM_CCM_CSCMR1_USDHC2_CLK_SEL		\
			BIT32(BS_CCM_CSCMR1_USDHC2_CLK_SEL)
#define BS_CCM_CSCMR1_USDHC1_CLK_SEL		16
#define BM_CCM_CSCMR1_USDHC1_CLK_SEL		\
			BIT32(BS_CCM_CSCMR1_USDHC1_CLK_SEL)
#define BS_CCM_CSCMR1_SSI3_CLK_SEL		14
#define BM_CCM_CSCMR1_SSI3_CLK_SEL		\
			SHIFT_U32(0x3, BS_CCM_CSCMR1_SSI3_CLK_SEL)
#define BS_CCM_CSCMR1_SSI2_CLK_SEL		12
#define BM_CCM_CSCMR1_SSI2_CLK_SEL		\
			SHIFT_U32(0x3, BS_CCM_CSCMR1_SSI2_CLK_SEL)
#define BS_CCM_CSCMR1_SSI1_CLK_SEL		10
#define BM_CCM_CSCMR1_SSI1_CLK_SEL		\
			SHIFT_U32(0x3, BS_CCM_CSCMR1_SSI1_CLK_SEL)
#define BS_CCM_CSCMR1_PERCLK_PODF		0
#define BM_CCM_CSCMR1_PERCLK_PODF		\
			SHIFT_U32(0x3F, BS_CCM_CSCMR1_PERCLK_PODF)

/* Define the bits in register CSCMR2 */
#define BS_CCM_CSCMR2_ESAI_PRE_SEL	19
#define BM_CCM_CSCMR2_ESAI_PRE_SEL	\
			SHIFT_U32(0x3, BS_CCM_CSCMR2_ESAI_PRE_SEL)
#define BS_CCM_CSCMR2_LDB_DI1_IPU_DIV	11
#define BM_CCM_CSCMR2_LDB_DI1_IPU_DIV	BIT32(BS_CCM_CSCMR2_LDB_DI1_IPU_DIV)
#define BS_CCM_CSCMR2_LDB_DI0_IPU_DIV	10
#define BM_CCM_CSCMR2_LDB_DI0_IPU_DIV	BIT32(BS_CCM_CSCMR2_LDB_DI1_IPU_DIV)
#define BS_CCM_CSCMR2_CAN_CLK_SEL	2
#define BM_CCM_CSCMR2_CAN_CLK_SEL	\
			SHIFT_U32(0x3F, BS_CCM_CSCMR2_CAN_CLK_SEL)

/* Define the bits in register CSCDR1 */
#define BS_CCM_CSCDR1_VPU_AXI_PODF	25
#define BM_CCM_CSCDR1_VPU_AXI_PODF	\
			SHIFT_U32(0x7, BS_CCM_CSCDR1_VPU_AXI_PODF)
#define BS_CCM_CSCDR1_USDHC4_PODF	22
#define BM_CCM_CSCDR1_USDHC4_PODF	\
			SHIFT_U32(0x7, BS_CCM_CSCDR1_USDHC4_PODF)
#define BS_CCM_CSCDR1_USDHC3_PODF	19
#define BM_CCM_CSCDR1_USDHC3_PODF	\
			SHIFT_U32(0x7, BS_CCM_CSCDR1_USDHC3_PODF)
#define BS_CCM_CSCDR1_USDHC2_PODF	16
#define BM_CCM_CSCDR1_USDHC2_PODF	\
			SHIFT_U32(0x7, BS_CCM_CSCDR1_USDHC2_PODF)
#define BS_CCM_CSCDR1_USDHC1_PODF	11
#define BM_CCM_CSCDR1_USDHC1_PODF	\
			SHIFT_U32(0x7, BS_CCM_CSCDR1_USDHC1_PODF)
#define BS_CCM_CSCDR1_USBOH3_CLK_PRED	8
#define BM_CCM_CSCDR1_USBOH3_CLK_PRED	\
			SHIFT_U32(0x7, BS_CCM_CSCDR1_USBOH3_CLK_PRED)
#define BS_CCM_CSCDR1_USBOH3_CLK_PODF	6
#define BM_CCM_CSCDR1_USBOH3_CLK_PODF	\
			SHIFT_U32(0x3, BS_CCM_CSCDR1_USBOH3_CLK_PODF)
#ifdef CONFIG_MX6SL
#define BS_CCM_CSCDR1_UART_CLK_SEL	6
#define BM_CCM_CSCDR1_UART_CLK_SEL	BIT32(BS_CCM_CSCDR1_UART_CLK_SEL)
#define BS_CCM_CSCDR1_UART_CLK_PODF	0
#define BM_CCM_CSCDR1_UART_CLK_PODF	SHIFT_U32(0x1F, BS_CCM_CSCDR1_UA)
#else
#define BS_CCM_CSCDR1_UART_CLK_PODF	0
#define BM_CCM_CSCDR1_UART_CLK_PODF	\
			SHIFT_U32(0x3F, BS_CCM_CSCDR1_UART_CLK_PODF)
#endif

/* Define the bits in register CS1CDR */
#define BS_CCM_CS1CDR_ESAI_CLK_PODF	25
#define BM_CCM_CS1CDR_ESAI_CLK_PODF	\
			SHIFT_U32(0x3F, BS_CCM_CS1CDR_ESAI_CLK_PODF)
#define BS_CCM_CS1CDR_SSI3_CLK_PODF	16
#define BM_CCM_CS1CDR_SSI3_CLK_PODF	SHIFT_U32(0x3F, BS_CCM_CS1CDR_SSI3)
#define BS_CCM_CS1CDR_ESAI_CLK_PRED	9
#define BM_CCM_CS1CDR_ESAI_CLK_PRED	\
			SHIFT_U32(0x3, BS_CCM_CS1CDR_ESAI_CLK_PRED)
#define BS_CCM_CS1CDR_SSI1_CLK_PRED	6
#define BM_CCM_CS1CDR_SSI1_CLK_PRED	\
			SHIFT_U32(0x7, BS_CCM_CS1CDR_SSI1_CLK_PRED)
#define BS_CCM_CS1CDR_SSI1_CLK_PODF	0
#define BM_CCM_CS1CDR_SSI1_CLK_PODF	\
			SHIFT_U32(0x3F, BS_CCM_CS1CDR_SSI1_CLK_PODF)

/* Define the bits in register CS2CDR */
#define BS_CCM_CS2CDR_ENFC_CLK_PODF	21
#define BM_CCM_CS2CDR_ENFC_CLK_PODF	\
			SHIFT_U32(0x3F, BS_CCM_CS2CDR_ENFC_CLK_PODF)
#define CCM_CS2CDR_ENFC_CLK_PODF(v)	\
			(SHIFT_U32(v, BS_CCM_CS2CDR_ENFC_CLK_PODF) & \
				BM_CCM_CS2CDR_ENFC_CLK_PODF)
#define BS_CCM_CS2CDR_ENFC_CLK_PRED	18
#define BM_CCM_CS2CDR_ENFC_CLK_PRED	\
			SHIFT_U32(0x7, BS_CCM_CS2CDR_ENFC_CLK_PRED)
#define CCM_CS2CDR_ENFC_CLK_PRED(v)	\
			(SHIFT_U32(v, BS_CCM_CS2CDR_ENFC_CLK_PRED) & \
				BM_CCM_CS2CDR_ENFC_CLK_PRED)
#define BS_CCM_CS2CDR_ENFC_CLK_SEL	16
#define BM_CCM_CS2CDR_ENFC_CLK_SEL	\
			SHIFT_U32(0x3, BS_CCM_CS2CDR_ENFC_CLK_SEL_OFFSET)
#define CCM_CS2CDR_ENFC_CLK_SEL(v)	\
			(SHIFT_U32(v, BS_CCM_CS2CDR_ENFC_CLK_SEL) & \
				BM_CCM_CS2CDR_ENFC_CLK_SEL)
#define BS_CCM_CS2CDR_LDB_DI1_CLK_SEL	12
#define BM_CCM_CS2CDR_LDB_DI1_CLK_SEL	\
			SHIFT_U32(0x7, BS_CCM_CS2CDR_LDB_DI1_CLK_SEL)
#define BS_CCM_CS2CDR_LDB_DI0_CLK_SEL	9
#define BM_CCM_CS2CDR_LDB_DI0_CLK_SEL	\
			SHIFT_U32(0x7, BS_CCM_CS2CDR_LDB_DI0_CLK_SEL)
#define BS_CCM_CS2CDR_SSI2_CLK_PRED	6
#define BM_CCM_CS2CDR_SSI2_CLK_PRED	\
			SHIFT_U32(0x7, BS_CCM_CS2CDR_SSI2_CLK_PRED)
#define BS_CCM_CS2CDR_SSI2_CLK_PODF	0
#define BM_CCM_CS2CDR_SSI2_CLK_PODF	\
			SHIFT_U32(0x3F, BS_CCM_CS2CDR_SSI2_CLK_PODF)

/* Define the bits in register CDCDR */
#define BS_CCM_CDCDR_HSI_TX_PODF	29
#define BM_CCM_CDCDR_HSI_TX_PODF	\
			SHIFT_U32(0x7, BS_CCM_CDCDR_HSI_TX_PODF)
#define BS_CCM_CDCDR_SPDIF0_CLK_PRED	25
#define BM_CCM_CDCDR_SPDIF0_CLK_PRED	\
			SHIFT_U32(0x7, BS_CCM_CDCDR_SPDIF0_CLK_PRED)
#define BS_CCM_CDCDR_HSI_TX_CLK_SEL	28
#define BM_CCM_CDCDR_HSI_TX_CLK_SEL	\
			BIT32(BS_CCM_CDCDR_HSI_TX_CLK_SEL)
#define BS_CCM_CDCDR_SPDIF0_CLK_PODF	19
#define BM_CCM_CDCDR_SPDIF0_CLK_PODF	\
			SHIFT_U32(0x7, BS_CCM_CDCDR_SPDIF0_CLK_PODF)
#define BS_CCM_CDCDR_SPDIF0_CLK_SEL	20
#define BM_CCM_CDCDR_SPDIF0_CLK_SEL	\
			SHIFT_U32(0x3, BS_CCM_CDCDR_SPDIF0_CLK_SEL)
#define BS_CCM_CDCDR_SPDIF1_CLK_PRED	12
#define BM_CCM_CDCDR_SPDIF1_CLK_PRED	\
			SHIFT_U32(0x7, BS_CCM_CDCDR_SPDIF1_CLK_PRED)
#define BS_CCM_CDCDR_SPDIF1_CLK_PODF	9
#define BM_CCM_CDCDR_SPDIF1_CLK_PODF	\
			SHIFT_U32(0x7, BS_CCM_CDCDR_SPDIF1_CLK_PODF)
#define BS_CCM_CDCDR_SPDIF1_CLK_SEL	7
#define BM_CCM_CDCDR_SPDIF1_CLK_SEL	\
			SHIFT_U32(0x3, BS_CCM_CDCDR_SPDIF1_CLK_SEL)

/* Define the bits in register CHSCCDR */
#define BS_CCM_CHSCCDR_IPU1_DI1_PRE_CLK_SEL	15
#define BM_CCM_CHSCCDR_IPU1_DI1_PRE_CLK_SEL	\
			SHIFT_U32(0x7, BS_CCM_CHSCCDR_IPU1_DI1_PRE_CLK_SEL)
#define BS_CCM_CHSCCDR_IPU1_DI1_PODF		12
#define BM_CCM_CHSCCDR_IPU1_DI1_PODF		\
			SHIFT_U32(0x7, BS_CCM_CHSCCDR_IPU1_DI1_PODF)
#define BS_CCM_CHSCCDR_IPU1_DI1_CLK_SEL		9
#define BM_CCM_CHSCCDR_IPU1_DI1_CLK_SEL		\
			SHIFT_U32(0x7, BS_CCM_CHSCCDR_IPU1_DI1_CLK_SEL)
#define BS_CCM_CHSCCDR_IPU1_DI0_PRE_CLK_SEL	6
#define BM_CCM_CHSCCDR_IPU1_DI0_PRE_CLK_SEL	\
			SHIFT_U32(0x7, BS_CCM_CHSCCDR_IPU1_DI0_PRE_CLK_SEL)
#define BS_CCM_CHSCCDR_IPU1_DI0_PODF		3
#define BM_CCM_CHSCCDR_IPU1_DI0_PODF		\
			SHIFT_U32(0x7, BS_CCM_CHSCCDR_IPU1_DI0_PODF)
#define BS_CCM_CHSCCDR_IPU1_DI0_CLK_SEL		0
#define BM_CCM_CHSCCDR_IPU1_DI0_CLK_SEL		\
			SHIFT_U32(0x7, BS_CCM_CHSCCDR_IPU1_DI0_CLK_SEL)

#define CHSCCDR_CLK_SEL_LDB_DI0			3
#define CHSCCDR_PODF_DIVIDE_BY_3		2
#define CHSCCDR_IPU_PRE_CLK_540M_PFD		5

/* Define the bits in register CSCDR2 */
#define BS_CCM_CSCDR2_ECSPI_CLK_PODF		19
#define BM_CCM_CSCDR2_ECSPI_CLK_PODF		\
			SHIFT_U32(0x3F, BS_CCM_CSCDR2_ECSPI_CLK_PODF)
#define BS_CCM_CHSCCDR_IPU2_DI1_PRE_CLK_SEL	15
#define BM_CCM_CHSCCDR_IPU2_DI1_PRE_CLK_SEL	\
			SHIFT_U32(0x7, BS_CCM_CHSCCDR_IPU2_DI1_PRE_CLK_SEL)
#define BS_CCM_CHSCCDR_IPU2_DI1_PODF		12
#define BM_CCM_CHSCCDR_IPU2_DI1_PODF		\
			SHIFT_U32(0x7, BS_CCM_CHSCCDR_IPU2_DI1_PODF)
#define BS_CCM_CHSCCDR_IPU2_DI1_CLK_SEL		9
#define BM_CCM_CHSCCDR_IPU2_DI1_CLK_SEL		\
			SHIFT_U32(0x7, BS_CCM_CHSCCDR_IPU2_DI1_CLK_SEL)
#define BS_CCM_CHSCCDR_IPU2_DI0_PRE_CLK_SEL	6
#define BM_CCM_CHSCCDR_IPU2_DI0_PRE_CLK_SEL	\
			SHIFT_U32(0x7, BS_CCM_CHSCCDR_IPU2_DI0_PRE_CLK_SEL)
#define BS_CCM_CHSCCDR_IPU2_DI0_PODF		3
#define BM_CCM_CHSCCDR_IPU2_DI0_PODF		\
			SHIFT_U32(0x7, BS_CCM_CHSCCDR_IPU2_DI0_PODF)
#define BS_CCM_CHSCCDR_IPU2_DI0_CLK_SEL		0
#define BM_CCM_CHSCCDR_IPU2_DI0_CLK_SEL		\
			SHIFT_U32(0x7, BS_CCM_CHSCCDR_IPU2_DI0_CLK_SEL)

/* Define the bits in register CSCDR3 */
#define BS_CCM_CSCDR3_IPU2_HSP_PODF		16
#define BM_CCM_CSCDR3_IPU2_HSP_PODF		\
			SHIFT_U32(0x7, BS_CCM_CSCDR3_IPU2_HSP_PODF)
#define BS_CCM_CSCDR3_IPU2_HSP_CLK_SEL		14
#define BM_CCM_CSCDR3_IPU2_HSP_CLK_SEL		\
			SHIFT_U32(0x3, BS_CCM_CSCDR3_IPU2_HSP_CLK_SEL)
#define BS_CCM_CSCDR3_IPU1_HSP_PODF		11
#define BM_CCM_CSCDR3_IPU1_HSP_PODF		\
			SHIFT_U32(0x7, BS_CCM_CSCDR3_IPU1_HSP_PODF)
#define BS_CCM_CSCDR3_IPU1_HSP_CLK_SEL		9
#define BM_CCM_CSCDR3_IPU1_HSP_CLK_SEL		\
			SHIFT_U32(0x3, BS_CCM_CSCDR3_IPU1_HSP_CLK_SEL)

/* Define the bits in register CDHIPR */
#define BS_CCM_CDHIPR_ARM_PODF_BUSY		16
#define BM_CCM_CDHIPR_ARM_PODF_BUSY		\
			BIT32(BS_CCM_CDHIPR_ARM_PODF_BUSY)
#define BS_CCM_CDHIPR_PERIPH_CLK_SEL_BUSY	5
#define BM_CCM_CDHIPR_PERIPH_CLK_SEL_BUSY	\
			BIT32(BS_CCM_CDHIPR_PERIPH_CLK_SEL_BUSY)
#define BS_CCM_CDHIPR_MMDC_CH0_PODF_BUSY	4
#define BM_CCM_CDHIPR_MMDC_CH0_PODF_BUSY	\
			BIT32(BS_CCM_CDHIPR_MMDC_CH0_PODF_BUSY)
#define BS_CCM_CDHIPR_PERIPH2_CLK_SEL_BUSY	3
#define BM_CCM_CDHIPR_PERIPH2_CLK_SEL_BUSY	\
			BIT32(BS_CCM_CDHIPR_PERIPH2_CLK_SEL_BUSY)
#define BS_CCM_CDHIPR_MMDC_CH1_PODF_BUSY	2
#define BM_CCM_CDHIPR_MMDC_CH1_PODF_BUSY	\
			BIT32(BS_CCM_CDHIPR_MMDC_CH1_PODF_BUSY)
#define BS_CCM_CDHIPR_AHB_PODF_BUSY		1
#define BM_CCM_CDHIPR_AHB_PODF_BUSY		\
			BIT32(BS_CCM_CDHIPR_AHB_PODF_BUSY)
#define BS_CCM_CDHIPR_AXI_PODF_BUSY		0
#define BM_CCM_CDHIPR_AXI_PODF_BUSY		\
			BIT32(BS_CCM_CDHIPR_AXI_PODF_BUSY)

/* Define the bits in register CLPCR */
#define BS_CCM_CLPCR_MASK_L2CC_IDLE		27
#define BM_CCM_CLPCR_MASK_L2CC_IDLE		\
			BIT32(BS_CCM_CLPCR_MASK_L2CC_IDLE)
#define BS_CCM_CLPCR_MASK_SCU_IDLE		26
#define BM_CCM_CLPCR_MASK_SCU_IDLE		\
			BIT32(BS_CCM_CLPCR_MASK_SCU_IDLE)
#define BS_CCM_CLPCR_MASK_CORE3_WFI		25
#define BM_CCM_CLPCR_MASK_CORE3_WFI		\
			BIT32(BS_CCM_CLPCR_MASK_CORE3_WFI)
#define BS_CCM_CLPCR_MASK_CORE2_WFI		24
#define BM_CCM_CLPCR_MASK_CORE2_WFI		\
			BIT32(BS_CCM_CLPCR_MASK_CORE2_WFI)
#define BS_CCM_CLPCR_MASK_CORE1_WFI		23
#define BM_CCM_CLPCR_MASK_CORE1_WFI		\
			BIT32(BS_CCM_CLPCR_MASK_CORE1_WFI)
#define BS_CCM_CLPCR_MASK_CORE0_WFI		22
#define BM_CCM_CLPCR_MASK_CORE0_WFI		\
			BIT32(BS_CCM_CLPCR_MASK_CORE0_WFI)
#define BS_CCM_CLPCR_BYP_MMDC_CH1_LPM_HS	21
#define BM_CCM_CLPCR_BYP_MMDC_CH1_LPM_HS	\
			BIT32(BS_CCM_CLPCR_BYP_MMDC_CH1_LPM_HS)
#define BS_CCM_CLPCR_BYP_MMDC_CH0_LPM_HS	19
#define BM_CCM_CLPCR_BYP_MMDC_CH0_LPM_HS	\
			BIT32(BS_CCM_CLPCR_BYP_MMDC_CH0_LPM_HS)
#define BS_CCM_CLPCR_WB_CORE_AT_LPM		17
#define BM_CCM_CLPCR_WB_CORE_AT_LPM		\
			BIT32(BS_CCM_CLPCR_WB_CORE_AT_LPM)
#define BS_CCM_CLPCR_WB_PER_AT_LPM		16
#define BM_CCM_CLPCR_WB_PER_AT_LPM		\
			BIT32(BS_CCM_CLPCR_WB_PER_AT_LPM)
#define BS_CCM_CLPCR_COSC_PWRDOWN		11
#define BM_CCM_CLPCR_COSC_PWRDOWN		\
			BIT32(BS_CCM_CLPCR_COSC_PWRDOWN)
#define BS_CCM_CLPCR_STBY_COUNT			9
#define BM_CCM_CLPCR_STBY_COUNT			\
			SHIFT_U32(0x3, BS_CCM_CLPCR_STBY_COUNT)
#define BS_CCM_CLPCR_VSTBY			8
#define BM_CCM_CLPCR_VSTBY			\
			BIT32(BS_CCM_CLPCR_VSTBY)
#define BS_CCM_CLPCR_DIS_REF_OSC		7
#define BM_CCM_CLPCR_DIS_REF_OSC		\
			BIT32(BS_CCM_CLPCR_DIS_REF_OSC)
#define BS_CCM_CLPCR_SBYOS			6
#define BM_CCM_CLPCR_SBYOS			\
			BIT32(BS_CCM_CLPCR_SBYOS)
#define BS_CCM_CLPCR_ARM_CLK_DIS_ON_LPM		5
#define BM_CCM_CLPCR_ARM_CLK_DIS_ON_LPM		\
			BIT32(BS_CCM_CLPCR_ARM_CLK_DIS_ON_LPM)
#define BS_CCM_CLPCR_LPSR_CLK_SEL		3
#define BM_CCM_CLPCR_LPSR_CLK_SEL		\
			SHIFT_U32(0x3, BS_CCM_CLPCR_LPSR_CLK_SEL)
#define BS_CCM_CLPCR_BYPASS_PMIC_VFUNC_RDY	2
#define BM_CCM_CLPCR_BYPASS_PMIC_VFUNC_RDY	\
			BIT32(BS_CCM_CLPCR_BYPASS_PMIC_VFUNC_RDY)
#define BS_CCM_CLPCR_LPM			0
#define BM_CCM_CLPCR_LPM			\
			SHIFT_U32(0x3, BS_CCM_CLPCR_LPM)

/* Define the bits in register CISR */
#define BS_CCM_CISR_ARM_PODF_LOADED		26
#define BM_CCM_CISR_ARM_PODF_LOADED		\
			BIT32(BS_CCM_CISR_ARM_PODF_LOADED)
#define BS_CCM_CISR_MMDC_CH0_PODF_LOADED	23
#define BM_CCM_CISR_MMDC_CH0_PODF_LOADED	\
			BIT32(BS_CCM_CISR_MMDC_CH0_PODF_LOADED)
#define BS_CCM_CISR_PERIPH_CLK_SEL_LOADED	22
#define BM_CCM_CISR_PERIPH_CLK_SEL_LOADED	\
			BIT32(BS_CCM_CISR_PERIPH_CLK_SEL_LOADED)
#define BS_CCM_CISR_MMDC_CH1_PODF_LOADED	21
#define BM_CCM_CISR_MMDC_CH1_PODF_LOADED	\
			BIT32(BS_CCM_CISR_MMDC_CH1_PODF_LOADED)
#define BS_CCM_CISR_AHB_PODF_LOADED		20
#define BM_CCM_CISR_AHB_PODF_LOADED		\
			BIT32(BS_CCM_CISR_AHB_PODF_LOADED)
#define BS_CCM_CISR_PERIPH2_CLK_SEL_LOADED	19
#define BM_CCM_CISR_PERIPH2_CLK_SEL_LOADED	\
			BIT32(BS_CCM_CISR_PERIPH2_CLK_SEL_LOADED)
#define BS_CCM_CISR_AXI_PODF_LOADED		17
#define BM_CCM_CISR_AXI_PODF_LOADED		\
			BIT32(BS_CCM_CISR_AXI_PODF_LOADED)
#define BS_CCM_CISR_COSC_READY			6
#define BM_CCM_CISR_COSC_READY			\
			BIT32(BS_CCM_CISR_COSC_READY)
#define BS_CCM_CISR_LRF_PLL			0
#define BM_CCM_CISR_LRF_PLL			\
			BIT32(BS_CCM_CISR_LRF_PLL)

/* Define the bits in register CIMR */
#define BS_CCM_CIMR_MASK_ARM_PODF_LOADED	26
#define BM_CCM_CIMR_MASK_ARM_PODF_LOADED	\
			BIT32(BS_CCM_CIMR_MASK_ARM_PODF_LOADED)
#define BS_CCM_CIMR_MASK_MMDC_CH0_PODF_LOADED	23
#define BM_CCM_CIMR_MASK_MMDC_CH0_PODF_LOADED	\
			BIT32(BS_CCM_CIMR_MASK_MMDC_CH0_PODF_LOADED)
#define BS_CCM_CIMR_MASK_PERIPH_CLK_SEL_LOADED	22
#define BM_CCM_CIMR_MASK_PERIPH_CLK_SEL_LOADED	\
			BIT32(BS_CCM_CIMR_MASK_PERIPH_CLK_SEL_LOADED)
#define BS_CCM_CIMR_MASK_MMDC_CH1_PODF_LOADED	21
#define BM_CCM_CIMR_MASK_MMDC_CH1_PODF_LOADED	\
			BIT32(BS_CCM_CIMR_MASK_MMDC_CH1_PODF_LOADED)
#define BS_CCM_CIMR_MASK_AHB_PODF_LOADED	20
#define BM_CCM_CIMR_MASK_AHB_PODF_LOADED	\
			BIT32(BS_CCM_CIMR_MASK_AHB_PODF_LOADED)
#define BS_CCM_CIMR_MASK_PERIPH2_CLK_SEL_LOADED	19
#define BM_CCM_CIMR_MASK_PERIPH2_CLK_SEL_LOADED	\
			BIT32(BS_CCM_CIMR_MASK_PERIPH2_CLK_SEL_LOADED)
#define BS_CCM_CIMR_MASK_AXI_PODF_LOADED	17
#define BM_CCM_CIMR_MASK_AXI_PODF_LOADED	\
			BIT32(BS_CCM_CIMR_MASK_AXI_PODF_LOADED)
#define BS_CCM_CIMR_MASK_COSC_READY		6
#define BM_CCM_CIMR_MASK_COSC_READY		\
			BIT32(BS_CCM_CIMR_MASK_COSC_READY)
#define BS_CCM_CIMR_MASK_LRF_PLL		0
#define BM_CCM_CIMR_MASK_LRF_PLL		\
			BIT32(BS_CCM_CIMR_MASK_LRF_PLL)

/* Define the bits in register CCOSR */
#define BS_CCM_CCOSR_CKO2_EN			24
#define BM_CCM_CCOSR_CKO2_EN			\
			BIT32(BS_CCM_CCOSR_CKO2_EN)
#define BS_CCM_CCOSR_CKO2_DIV			21
#define BM_CCM_CCOSR_CKO2_DIV			\
			SHIFT_U32(0x7, BS_CCM_CCOSR_CKO2_DIV)
#define BS_CCM_CCOSR_CKO2_SEL			16
#define BM_CCM_CCOSR_CKO2_SEL			\
			SHIFT_U32(0x1F, BS_CCM_CCOSR_CKO2_SEL)
#define BS_CCM_CCOSR_CLK_OUT_SEL		8
#define BM_CCM_CCOSR_CLK_OUT_SEL_CKO2		\
			BIT32(BS_CCM_CCOSR_CLK_OUT_SEL)
#define BS_CCM_CCOSR_CKOL_EN			7
#define BM_CCM_CCOSR_CKOL_EN			\
			BIT32(BS_CCM_CCOSR_CKOL_EN)
#define BS_CCM_CCOSR_CKOL_DIV			4
#define BM_CCM_CCOSR_CKOL_DIV			\
			SHIFT_U32(0x7, BS_CCM_CCOSR_CKOL_DIV)
#define BS_CCM_CCOSR_CKOL_SEL			0
#define BM_CCM_CCOSR_CKOL_SEL			\
			SHIFT_U32(0xF, BS_CCM_CCOSR_CKOL_SEL)

/* Define the bits in registers CGPR */
#define BS_CCM_CGPR_INT_MEM_CLK_LPM		17
#define BM_CCM_CGPR_INT_MEM_CLK_LPM		\
			BIT32(BS_CCM_CGPR_INT_MEM_CLK_LPM)
#define BS_CCM_CGPR_EFUSE_PROG_SUPPLY_GATE	4
#define BM_CCM_CGPR_EFUSE_PROG_SUPPLY_GATE	\
			BIT32(BS_CCM_CGPR_EFUSE_PROG_SUPPLY_GATE)
#define BS_CCM_CGPR_MMDC_EXT_CLK_DIS		2
#define BM_CCM_CGPR_MMDC_EXT_CLK_DIS		\
			BIT32(BS_CCM_CGPR_MMDC_EXT_CLK_DIS)
#define BS_CCM_CGPR_PMIC_DELAY_SCALER		0
#define BM_CCM_CGPR_PMIC_DELAY_SCALER		\
			BIT32(BS_CCM_CGPR_PMIC_DELAY_SCALER)

/* Define the bits in registers CCGRx */
#define BS_CCM_CCGR0_AIPS_TZ1			0
#define BM_CCM_CCGR0_AIPS_TZ1			\
			SHIFT_U32(3, BS_CCM_CCGR0_AIPS_TZ1)
#define BS_CCM_CCGR0_AIPS_TZ2			2
#define BM_CCM_CCGR0_AIPS_TZ2			\
			SHIFT_U32(3, BS_CCM_CCGR0_AIPS_TZ2)
#define BS_CCM_CCGR0_APBHDMA			4
#define BM_CCM_CCGR0_APBHDMA			\
			SHIFT_U32(3, BS_CCM_CCGR0_APBHDMA)
#define BS_CCM_CCGR0_ASRC			6
#define BM_CCM_CCGR0_ASRC			\
			SHIFT_U32(3, BS_CCM_CCGR0_ASRC)
#define BS_CCM_CCGR0_CAAM_SECURE_MEM		8
#define BM_CCM_CCGR0_CAAM_SECURE_MEM		\
			SHIFT_U32(3, BS_CCM_CCGR0_CAAM_SECURE_MEM)
#define BS_CCM_CCGR0_CAAM_WRAPPER_ACLK		10
#define BM_CCM_CCGR0_CAAM_WRAPPER_ACLK		\
			SHIFT_U32(3, BS_CCM_CCGR0_CAAM_WRAPPER_ACLK)
#define BS_CCM_CCGR0_CAAM_WRAPPER_IPG		12
#define BM_CCM_CCGR0_CAAM_WRAPPER_IPG		\
			SHIFT_U32(3, BS_CCM_CCGR0_CAAM_WRAPPER_IPG)
#define BS_CCM_CCGR0_CAN1			14
#define BM_CCM_CCGR0_CAN1			SHIFT_U32(3, BS_CCM_CCGR0_CAN1)
#define BS_CCM_CCGR0_CAN1_SERIAL		16
#define BM_CCM_CCGR0_CAN1_SERIAL		\
			SHIFT_U32(3, BS_CCM_CCGR0_CAN1_SERIAL)
#define BS_CCM_CCGR0_CAN2			18
#define BM_CCM_CCGR0_CAN2			SHIFT_U32(3, BS_CCM_CCGR0_CAN2)
#define BS_CCM_CCGR0_CAN2_SERIAL		20
#define BM_CCM_CCGR0_CAN2_SERIAL		\
			SHIFT_U32(3, BS_CCM_CCGR0_CAN2_SERIAL)
#define BS_CCM_CCGR0_CHEETAH_DBG_CLK		22
#define BM_CCM_CCGR0_CHEETAH_DBG_CLK		\
			SHIFT_U32(3, BS_CCM_CCGR0_CHEETAH_DBG_CLK)
#define BS_CCM_CCGR0_DCIC1		24
#define BM_CCM_CCGR0_DCIC1		SHIFT_U32(3, BS_CCM_CCGR0_DCIC1)
#define BS_CCM_CCGR0_DCIC2		26
#define BM_CCM_CCGR0_DCIC2		SHIFT_U32(3, BS_CCM_CCGR0_DCIC2)
#define BS_CCM_CCGR0_DTCP		28
#define BM_CCM_CCGR0_DTCP		SHIFT_U32(3, BS_CCM_CCGR0_DTCP)

#define BS_CCM_CCGR1_ECSPI1S		0
#define BM_CCM_CCGR1_ECSPI1S		SHIFT_U32(3, BS_CCM_CCGR1_ECSPI1S)
#define BS_CCM_CCGR1_ECSPI2S		2
#define BM_CCM_CCGR1_ECSPI2S		SHIFT_U32(3, BS_CCM_CCGR1_ECSPI2S)
#define BS_CCM_CCGR1_ECSPI3S		4
#define BM_CCM_CCGR1_ECSPI3S		SHIFT_U32(3, BS_CCM_CCGR1_ECSPI3S)
#define BS_CCM_CCGR1_ECSPI4S		6
#define BM_CCM_CCGR1_ECSPI4S		SHIFT_U32(3, BS_CCM_CCGR1_ECSPI4S)
#define BS_CCM_CCGR1_ECSPI5S		8
#define BM_CCM_CCGR1_ECSPI5S		SHIFT_U32(3, BS_CCM_CCGR1_ECSPI5S)
#define BS_CCM_CCGR1_ENET_CLK_ENABLE	10
#define BM_CCM_CCGR1_ENET_CLK_ENABLE	\
			(3 << BS_CCM_CCGR1_ENET_CLK_ENABLE)
#define BS_CCM_CCGR1_EPIT1S		12
#define BM_CCM_CCGR1_EPIT1S		SHIFT_U32(3, BS_CCM_CCGR1_EPIT1S)
#define BS_CCM_CCGR1_EPIT2S		14
#define BM_CCM_CCGR1_EPIT2S		SHIFT_U32(3, BS_CCM_CCGR1_EPIT2S)
#define BS_CCM_CCGR1_ESAIS		16
#define BM_CCM_CCGR1_ESAIS		SHIFT_U32(3, BS_CCM_CCGR1_ESAIS)
#define BS_CCM_CCGR1_GPT_BUS		20
#define BM_CCM_CCGR1_GPT_BUS		SHIFT_U32(3, BS_CCM_CCGR1_GPT_BUS)
#define BS_CCM_CCGR1_GPT_SERIAL		22
#define BM_CCM_CCGR1_GPT_SERIAL		SHIFT_U32(3, BS_CCM_CCGR1_GPT_SERIAL)
#define BS_CCM_CCGR1_GPU2D		24
#define BM_CCM_CCGR1_GPU2D		SHIFT_U32(3, BS_CCM_CCGR1_GPU2D)
#define BS_CCM_CCGR1_GPU3D		26
#define BM_CCM_CCGR1_GPU3D		SHIFT_U32(3, BS_CCM_CCGR1_GPU3D)

#define BS_CCM_CCGR2_HDMI_TX_IAHBCLK	0
#define BM_CCM_CCGR2_HDMI_TX_IAHBCLK	\
			SHIFT_U32(3, BS_CCM_CCGR2_HDMI_TX_IAHBCLK)
#define BS_CCM_CCGR2_HDMI_TX_ISFRCLK	4
#define BM_CCM_CCGR2_HDMI_TX_ISFRCLK	\
			SHIFT_U32(3, BS_CCM_CCGR2_HDMI_TX_ISFRCLK)
#define BS_CCM_CCGR2_I2C1_SERIAL	6
#define BM_CCM_CCGR2_I2C1_SERIAL	SHIFT_U32(3, BS_CCM_CCGR2_I2C1_SERIAL)
#define BS_CCM_CCGR2_I2C2_SERIAL	8
#define BM_CCM_CCGR2_I2C2_SERIAL	SHIFT_U32(3, BS_CCM_CCGR2_I2C2_SERIAL)
#define BS_CCM_CCGR2_I2C3_SERIAL	10
#define BM_CCM_CCGR2_I2C3_SERIAL	SHIFT_U32(3, BS_CCM_CCGR2_I2C3_SERIAL)
#define BS_CCM_CCGR2_OCOTP_CTRL		12
#define BM_CCM_CCGR2_OCOTP_CTRL		SHIFT_U32(3, BS_CCM_CCGR2_OCOTP_CTRL)
#define BS_CCM_CCGR2_IOMUX_IPT_CLK_IO	14
#define BM_CCM_CCGR2_IOMUX_IPT_CLK_IO	\
			SHIFT_U32(3, BS_CCM_CCGR2_IOMUX_IPT_CLK_IO)
#define BS_CCM_CCGR2_IPMUX1		16
#define BM_CCM_CCGR2_IPMUX1		SHIFT_U32(3, BS_CCM_CCGR2_IPMUX1)
#define BS_CCM_CCGR2_IPMUX2		18
#define BM_CCM_CCGR2_IPMUX2		SHIFT_U32(3, BS_CCM_CCGR2_IPMUX2)
#define BS_CCM_CCGR2_IPMUX3		20
#define BM_CCM_CCGR2_IPMUX3		SHIFT_U32(3, BS_CCM_CCGR2_IPMUX3)
#define BS_CCM_CCGR2_IPSYNC_IP2APB_TZASC1_IPGS	22
#define BM_CCM_CCGR2_IPSYNC_IP2APB_TZASC1_IPGS	\
			SHIFT_U32(3, BS_CCM_CCGR2_IPSYNC_IP2APB_TZASC1_IPGS)
#define BS_CCM_CCGR2_IPSYNC_IP2APB_TZASC2_IPG	24
#define BM_CCM_CCGR2_IPSYNC_IP2APB_TZASC2_IPG	\
			SHIFT_U32(3, BS_CCM_CCGR2_IPSYNC_IP2APB_TZASC2_IPG)
#define BS_CCM_CCGR2_IPSYNC_VDOA_IPG_MASTER_CLK	26
#define BM_CCM_CCGR2_IPSYNC_VDOA_IPG_MASTER_CLK	\
			SHIFT_U32(3, BS_CCM_CCGR2_IPSYNC_VDOA_IPG_MASTER_CLK)

#define BS_CCM_CCGR3_IPU1_IPU		0
#define BM_CCM_CCGR3_IPU1_IPU		SHIFT_U32(3, BS_CCM_CCGR3_IPU1_IPU)
#define BS_CCM_CCGR3_IPU1_IPU_DI0	2
#define BM_CCM_CCGR3_IPU1_IPU_DI0	SHIFT_U32(3, BS_CCM_CCGR3_IPU1_IPU_DI0)
#define BS_CCM_CCGR3_IPU1_IPU_DI1	4
#define BM_CCM_CCGR3_IPU1_IPU_DI1	SHIFT_U32(3, BS_CCM_CCGR3_IPU1_IPU_DI1)
#define BS_CCM_CCGR3_IPU2_IPU		6
#define BM_CCM_CCGR3_IPU2_IPU		SHIFT_U32(3, BS_CCM_CCGR3_IPU2_IPU)
#define BS_CCM_CCGR3_IPU2_IPU_DI0	8
#define BM_CCM_CCGR3_IPU2_IPU_DI0	SHIFT_U32(3, BS_CCM_CCGR3_IPU2_IPU_DI0)
#define BS_CCM_CCGR3_IPU2_IPU_DI1	10
#define BM_CCM_CCGR3_IPU2_IPU_DI1	SHIFT_U32(3, BS_CCM_CCGR3_IPU2_IPU_DI1)
#define BS_CCM_CCGR3_LDB_DI0		12
#define BM_CCM_CCGR3_LDB_DI0		SHIFT_U32(3, BS_CCM_CCGR3_LDB_DI0)
#define BS_CCM_CCGR3_LDB_DI1		14
#define BM_CCM_CCGR3_LDB_DI1		SHIFT_U32(3, BS_CCM_CCGR3_LDB_DI1)
#define BS_CCM_CCGR3_MIPI_CORE_CFG	16
#define BM_CCM_CCGR3_MIPI_CORE_CFG	\
				SHIFT_U32(3, BS_CCM_CCGR3_MIPI_CORE_CFG)
#define BS_CCM_CCGR3_MLB			18
#define BM_CCM_CCGR3_MLB		SHIFT_U32(3, BS_CCM_CCGR3_MLB)
#define BS_CCM_CCGR3_MMDC_CORE_ACLK_FAST_CORE_P0	20
#define BM_CCM_CCGR3_MMDC_CORE_ACLK_FAST_CORE_P0	\
			SHIFT_U32(3, BS_CCM_CCGR3_MMDC_CORE_ACLK_FAST_CORE_P0)
#define BS_CCM_CCGR3_MMDC_CORE_ACLK_FAST_CORE_P1	22
#define BM_CCM_CCGR3_MMDC_CORE_ACLK_FAST_CORE_P1	\
			SHIFT_U32(3, BS_CCM_CCGR3_MMDC_CORE_ACLK_FAST_CORE_P1)
#define BS_CCM_CCGR3_MMDC_CORE_IPG_CLK_P0		24
#define BM_CCM_CCGR3_MMDC_CORE_IPG_CLK_P0		\
			SHIFT_U32(3, BS_CCM_CCGR3_MMDC_CORE_IPG_CLK_P0)
#define BS_CCM_CCGR3_MMDC_CORE_IPG_CLK_P1	26
#define BM_CCM_CCGR3_MMDC_CORE_IPG_CLK_P1	\
			SHIFT_U32(3, BS_CCM_CCGR3_MMDC_CORE_IPG_CLK_P1)
#define BS_CCM_CCGR3_OCRAM		28
#define BM_CCM_CCGR3_OCRAM		SHIFT_U32(3, BS_CCM_CCGR3_OCRAM)
#define BS_CCM_CCGR3_OPENVGAXICLK	30
#define BM_CCM_CCGR3_OPENVGAXICLK	\
			SHIFT_U32(3, BS_CCM_CCGR3_OPENVGAXICLK)

#define BS_CCM_CCGR4_PCIE			0
#define BM_CCM_CCGR4_PCIE			SHIFT_U32(3, BS_CCM_CCGR4_PCIE)
#define BS_CCM_CCGR4_PL301_MX6QFAST1_S133	8
#define BM_CCM_CCGR4_PL301_MX6QFAST1_S133	\
			SHIFT_U32(3, BS_CCM_CCGR4_PL301_MX6QFAST1_S133)
#define BS_CCM_CCGR4_PL301_MX6QPER1_BCH		12
#define BM_CCM_CCGR4_PL301_MX6QPER1_BCH		\
			SHIFT_U32(3, BS_CCM_CCGR4_PL301_MX6QPER1_BCH)
#define BS_CCM_CCGR4_PL301_MX6QPER2_MAINCLK_ENABLE	14
#define BM_CCM_CCGR4_PL301_MX6QPER2_MAINCLK_ENABLE	\
		SHIFT_U32(3, BS_CCM_CCGR4_PL301_MX6QPER2_MAINCLK_ENABLE)
#define BS_CCM_CCGR4_PWM1				16
#define BM_CCM_CCGR4_PWM1				\
			SHIFT_U32(3, BS_CCM_CCGR4_PWM1)
#define BS_CCM_CCGR4_PWM2				18
#define BM_CCM_CCGR4_PWM2				\
			SHIFT_U32(3, BS_CCM_CCGR4_PWM2)
#define BS_CCM_CCGR4_PWM3				20
#define BM_CCM_CCGR4_PWM3				\
			SHIFT_U32(3, BS_CCM_CCGR4_PWM3)
#define BS_CCM_CCGR4_PWM4				22
#define BM_CCM_CCGR4_PWM4				\
			SHIFT_U32(3, BS_CCM_CCGR4_PWM4)
#define BS_CCM_CCGR4_RAWNAND_U_BCH_INPUT_APB		24
#define BM_CCM_CCGR4_RAWNAND_U_BCH_INPUT_APB		\
		SHIFT_U32(3, BS_CCM_CCGR4_RAWNAND_U_BCH_INPUT_APB)
#define BS_CCM_CCGR4_RAWNAND_U_GPMI_BCH_INPUT_BCH	26
#define BM_CCM_CCGR4_RAWNAND_U_GPMI_BCH_INPUT_BCH	\
		SHIFT_U32(3, BS_CCM_CCGR4_RAWNAND_U_GPMI_BCH_INPUT_BCH)
#define BS_CCM_CCGR4_RAWNAND_U_GPMI_BCH_INPUT_GPMI_IO	28
#define BM_CCM_CCGR4_RAWNAND_U_GPMI_BCH_INPUT_GPMI_IO	\
		SHIFT_U32(3, BS_CCM_CCGR4_RAWNAND_U_GPMI_BCH_INPUT_GPMI_IO)
#define BS_CCM_CCGR4_RAWNAND_U_GPMI_INPUT_APB		30
#define BM_CCM_CCGR4_RAWNAND_U_GPMI_INPUT_APB		\
		SHIFT_U32(3, BS_CCM_CCGR4_RAWNAND_U_GPMI_INPUT_APB)

#define BS_CCM_CCGR5_ROM	0
#define BM_CCM_CCGR5_ROM	SHIFT_U32(3, BS_CCM_CCGR5_ROM)
#define BS_CCM_CCGR5_SATA	4
#define BM_CCM_CCGR5_SATA	SHIFT_U32(3, BS_CCM_CCGR5_SATA)
#define BS_CCM_CCGR5_SDMA	6
#define BM_CCM_CCGR5_SDMA	SHIFT_U32(3, BS_CCM_CCGR5_SDMA)
#define BS_CCM_CCGR5_SPBA	12
#define BM_CCM_CCGR5_SPBA	SHIFT_U32(3, BS_CCM_CCGR5_SPBA)
#define BS_CCM_CCGR5_SPDIF	14
#define BM_CCM_CCGR5_SPDIF	SHIFT_U32(3, BS_CCM_CCGR5_SPDIF)
#define BS_CCM_CCGR5_SSI1	18
#define BM_CCM_CCGR5_SSI1	SHIFT_U32(3, BS_CCM_CCGR5_SSI1)
#define BS_CCM_CCGR5_SSI2	20
#define BM_CCM_CCGR5_SSI2	SHIFT_U32(3, BS_CCM_CCGR5_SSI2)
#define BS_CCM_CCGR5_SSI3	22
#define BM_CCM_CCGR5_SSI3	SHIFT_U32(3, BS_CCM_CCGR5_SSI3)
#define BS_CCM_CCGR5_UART	24
#define BM_CCM_CCGR5_UART	SHIFT_U32(3, BS_CCM_CCGR5_UART)
#define BS_CCM_CCGR5_UART_SERIAL	26
#define BM_CCM_CCGR5_UART_SERIAL	SHIFT_U32(3, BS_CCM_CCGR5_UART_SERIAL)

#define BS_CCM_CCGR6_USBOH3		0
#define BM_CCM_CCGR6_USBOH3		SHIFT_U32(3, BS_CCM_CCGR6_USBOH3)
#define BS_CCM_CCGR6_USDHC1		2
#define BM_CCM_CCGR6_USDHC1		SHIFT_U32(3, BS_CCM_CCGR6_USDHC1)
#define BS_CCM_CCGR6_USDHC2		4
#define BM_CCM_CCGR6_USDHC2		SHIFT_U32(3, BS_CCM_CCGR6_USDHC2)
#define BS_CCM_CCGR6_USDHC3		6
#define BM_CCM_CCGR6_USDHC3		SHIFT_U32(3, BS_CCM_CCGR6_USDHC3)
#define BS_CCM_CCGR6_USDHC4		8
#define BM_CCM_CCGR6_USDHC4		SHIFT_U32(3, BS_CCM_CCGR6_USDHC4)
#define BS_CCM_CCGR6_EMI_SLOW		10
#define BM_CCM_CCGR6_EMI_SLOW		SHIFT_U32(3, BS_CCM_CCGR6_EMI_SLOW)
#define BS_CCM_CCGR6_VDOAXICLK		12
#define BM_CCM_CCGR6_VDOAXICLK		SHIFT_U32(3, BS_CCM_CCGR6_VDOAXICLK)


/*
 * Define Analog Macros and common bits
 */
#define BS_CCM_ANALOG_PLL_LOCK			31
#define BM_CCM_ANALOG_PLL_LOCK			\
			BIT32(BS_CCM_ANALOG_PLL_LOCK)
#define BS_CCM_ANALOG_PLL_BYPASS		16
#define BM_CCM_ANALOG_PLL_BYPASS		\
			BIT32(BS_CCM_ANALOG_PLL_BYPASS)
#define BS_CCM_ANALOG_PLL_BYPASS_CLK_SRC	14
#define BM_CCM_ANALOG_PLL_BYPASS_CLK_SRC	\
			SHIFT_U32(0x3, BS_CCM_ANALOG_PLL_BYPASS_CLK_SRC)
#define CCM_ANALOG_PLL_BYPASS_CLK_SRC(clk)	\
			(SHIFT_U32(clk, BS_CCM_ANALOG_PLL_BYPASS_CLK_SRC) & \
				BM_CCM_ANALOG_PLL_BYPASS_CLK_SRC)
#define CCM_ANALOG_PLL_BYPASS_CLK_SRC_CLK24M	0x0
#define CCM_ANALOG_PLL_BYPASS_CLK_SRC_CLK1	0x1
#define CCM_ANALOG_PLL_BYPASS_CLK_SRC_CLK2	0x2
#define CCM_ANALOG_PLL_BYPASS_CLK_SRC_XOR	0x3

#define BS_CCM_ANALOG_PLL_ENABLE	13
#define BM_CCM_ANALOG_PLL_ENABLE	BIT32(BS_CCM_ANALOG_PLL_ENABLE)
#define BS_CCM_ANALOG_PLL_POWERDOWN	12
#define BM_CCM_ANALOG_PLL_POWERDOWN	BIT32(BS_CCM_ANALOG_PLL_POWERDOWN)
#define BS_CCM_ANALOG_PLL_DIV_SELECT	0

/*
 * Specific Analog bits definition
 */
#define BS_CCM_ANALOG_PLL_ARM_PLL_SEL	19
#define BM_CCM_ANALOG_PLL_ARM_PLL_SEL	BIT32(BS_CCM_ANALOG_PLL_ARM_PLL_SEL)
#define BS_CCM_ANALOG_PLL_ARM_LVDS_24MHZ_SEL	18
#define BM_CCM_ANALOG_PLL_ARM_LVDS_24MHZ_SEL	\
			BIT32(BS_CCM_ANALOG_PLL_ARM_LVDS_24MHZ_SEL)
#define BS_CCM_ANALOG_PLL_ARM_LVDS_SEL		17
#define BM_CCM_ANALOG_PLL_ARM_LVDS_SEL		\
			BIT32(BS_CCM_ANALOG_PLL_ARM_LVDS_SEL)
#define BM_CCM_ANALOG_PLL_ARM_DIV_SELECT	\
			SHIFT_U32(0x7F, BS_CCM_ANALOG_PLL_DIV_SELECT)

#endif /* __MX6_CCM_REGS_H__ */
