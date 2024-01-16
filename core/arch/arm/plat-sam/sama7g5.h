/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Header file for ATSAMA7G54
 *
 * Copyright (c) 2023 Microchip Technology Inc. and its subsidiaries.
 */

#ifndef _SAMA7G54_H_
#define _SAMA7G54_H_

/*
 * SAMA7G54 definitions
 * This file defines all structures and symbols for SAMA7G54:
 *   - registers and bitfields
 *   - peripheral base address
 *   - peripheral ID
 *   - PIO definitions
 */

#define GIC_DISTRIBUTOR_BASE 0xE8C11000 /* Base for GIC distributor interface */
#define GIC_INTERFACE_BASE   0xE8C12000 /* Base address for GIC CPU interface */
#define GICC_SIZE            0x1000
#define GICD_SIZE            0x1000

/* ************************************************************************** */
/*  PERIPHERAL ID DEFINITIONS FOR SAMA7G54                                    */
/* ************************************************************************** */
#define ID_DWDT_SW         0 /* Dual Watchdog Timer, Secure World (DWDT_SW) */
#define ID_DWDT_NSW        1 /* DWDT Non Secure World, interrupt (DWDT_NSW) */
#define ID_DWDT_NSW_ALARM  2 /* DWDT Non Secure World Alarm, interrupt */
#define ID_SCKC            4 /* Slow Clock Controller (SCKC) */
#define ID_SHDWC           5 /* SHutDoWn Controller (SHDWC) */
#define ID_RSTC            6 /* Reset Controller (RSTC) */
#define ID_RTC             7 /* Real-Time Clock (RTC) */
#define ID_RTT             8 /* Real-Time Timer (RTT) */
#define ID_CHIPID          9 /* Chip Identifier (CHIPID) */
#define ID_PMC            10 /* Power Management Controller (PMC) */
#define ID_PIOA           11 /* For PIO 0 to 31 (PIOA) */
#define ID_PIOB           12 /* For PIO 32 to 63, interrupt (PIOB) */
#define ID_PIOC           13 /* For PIO 64 to 95, interrupt (PIOC) */
#define ID_PIOD           14 /* For PIO 96 to 127, interrupt (PIOD) */
#define ID_PIOE           15 /* For PIO 128 to 136, interrupt (PIOE) */
#define ID_SECUMOD        17 /* Security Module (SECUMOD) */
#define ID_SECURAM        18 /* Secret RAM (SECURAM) */
#define ID_SFR            19 /* Special Function Register (SFR) */
#define ID_SFRBU          20 /* Special Function Register in BackUp zone */
#define ID_HSMC           21 /* Static Memory Controller - NAND (HSMC) */
#define ID_XDMAC0         22 /* DMA 0, mem to periph, 32 Channels (XDMAC0) */
#define ID_XDMAC1         23 /* DMA 1, mem to periph, 32 Channels (XDMAC1) */
#define ID_XDMAC2         24 /* DMA 2, mem to mem, 4 Channels (XDMAC2) */
#define ID_ACC            25 /* Analog Comparator Controller (ACC) */
#define ID_ADC            26 /* Analog-to-Digital Converter (ADC) */
#define ID_AES            27 /* Advanced Encryption Standard (AES) */
#define ID_TZAESBASC      28 /* TZ AES Bridge - Address Space Controlller */
#define ID_ASRC           30 /* Asynchronous Sample Rate Converter (ASRC) */
#define ID_CPKCC          32 /* Classic Public Key Cryptography Controller */
#define ID_CSI            33 /* CSI 2 between ISC and MIPI PHY (CSI) */
#define ID_CSI2DC         34 /* CSI to Demultiplexer Controller (CSI2DC) */
#define ID_DDRPUBL        35 /* DDR SDRAM PHY Utility Block "Lite" aka PUBL */
#define ID_DDRUMCTL       36 /* Universal DDR-SDRAM Memory Controller */
#define ID_EIC            37 /* External  Interrupt Controller (EIC) */
#define ID_FLEXCOM0       38 /* Flexcom 0 (FLEXCOM0) */
#define ID_FLEXCOM1       39 /* Flexcom 1 (FLEXCOM1) */
#define ID_FLEXCOM2       40 /* Flexcom 2 (FLEXCOM2) */
#define ID_FLEXCOM3       41 /* Flexcom 3 (FLEXCOM3) */
#define ID_FLEXCOM4       42 /* Flexcom 4 (FLEXCOM4) */
#define ID_FLEXCOM5       43 /* Flexcom 5 (FLEXCOM5) */
#define ID_FLEXCOM6       44 /* Flexcom 6 (FLEXCOM6) */
#define ID_FLEXCOM7       45 /* Flexcom 7 (FLEXCOM7) */
#define ID_FLEXCOM8       46 /* Flexcom 8 (FLEXCOM8) */
#define ID_FLEXCOM9       47 /* Flexcom 9 (FLEXCOM9) */
#define ID_FLEXCOM10      48 /* Flexcom 10 (FLEXCOM10) */
#define ID_FLEXCOM11      49 /* Flexcom 11 (FLEXCOM11) */
#define ID_GMAC0          51 /* Gigabit Ethernet MAC (GMAC0) */
#define ID_GMAC1          52 /* Ethernet MAC (GMAC1) */
#define ID_GMAC0_TSU      53 /* GMAC - TSU Generic Clock - No Interrupt */
#define ID_GMAC1_TSU      54 /* EMAC - TSU Generic Clock - No Interrupt */
#define ID_ICM            55 /* Integrity Check Monitor (ICM) */
#define ID_ISC            56 /* Camera Interface (ISC) */
#define ID_I2SMCC0        57 /* Inter-IC Sound Controller 0 (I2SMCC0) */
#define ID_I2SMCC1        58 /* Inter-IC Sound Controller 1 (I2SMCC1) */
#define ID_MATRIX         60 /* HSS AHB Matrix (MATRIX) */
#define ID_MCAN0          61 /* Master CAN 0 (MCAN0) */
#define ID_MCAN1          62 /* Master CAN 1 (MCAN1) */
#define ID_MCAN2          63 /* Master CAN 2 (MCAN2) */
#define ID_MCAN3          64 /* Master CAN 3 (MCAN3) */
#define ID_MCAN4          65 /* Master CAN 4 (MCAN4) */
#define ID_MCAN5          66 /* Master CAN 5 (MCAN5) */
#define ID_OTPC           67 /* One Time Programmable memory Controller */
#define ID_PDMC0          68 /* Pulse Density Modulation Controller 0 */
#define ID_PDMC1          69 /* Pulse Density Modulation Controller 1 */
#define ID_PIT64B0        70 /* 64-bit Periodic Interval Timer 0 (PIT64B0) */
#define ID_PIT64B1        71 /* 64-bit Periodic Interval Timer 1 (PIT64B1) */
#define ID_PIT64B2        72 /* 64-bit Periodic Interval Timer 2 (PIT64B2) */
#define ID_PIT64B3        73 /* 64-bit Periodic Interval Timer 3 (PIT64B3) */
#define ID_PIT64B4        74 /* 64-bit Periodic Interval Timer 4 (PIT64B4) */
#define ID_PIT64B5        75 /* 64-bit Periodic Interval Timer 5 (PIT64B5) */
#define ID_PWM            77 /* Pulse Width Modulation (PWM) */
#define ID_QSPI0          78 /* Quad IO Serial Peripheral Interface 0 */
#define ID_QSPI1          79 /* Quad IO Serial Peripheral Interface 1 */
#define ID_SDMMC0         80 /* Ultra HS SD Host controller 0 (eMMC 5.1) */
#define ID_SDMMC1         81 /* Ultra HS SD Host controller 1 (eMMC 4.51) */
#define ID_SDMMC2         82 /* Ultra HS SD Host controller 2 (eMMC 4.51) */
#define ID_SHA            83 /* Secure Hash Algorithm (SHA) */
#define ID_SPDIFRX        84 /* Sony Philips Digital Interface RX (SPDIFRX) */
#define ID_SPDIFTX        85 /* Sony Philips Digital Interface TX (SPDIFTX) */
#define ID_SSC0           86 /* Synchronous Serial Interface 0 (SSC0) */
#define ID_SSC1           87 /* Synchronous Serial Interface 1 (SSC1) */
#define ID_TC0_CHANNEL0   88 /* 32-bit Timer Counter 0 Channel 0 */
#define ID_TC0_CHANNEL1   89 /* 32-bit Timer Counter 0 Channel 1 interrupt */
#define ID_TC0_CHANNEL2   90 /* 32-bit Timer Counter 0 Channel 2 interrupt */
#define ID_TC1_CHANNEL0   91 /* 32-bit Timer Counter 1 Channel 0 */
#define ID_TC1_CHANNEL1   92 /* 32-bit Timer Counter 1 Channel 1 interrupt */
#define ID_TC1_CHANNEL2   93 /* 32-bit Timer Counter 1 Channel 2 interrupt */
#define ID_TCPCA          94 /* USB Type-C Port Controller A (TCPCA) */
#define ID_TCPCB          95 /* USB Type-C Port Controller B (TCPCB) */
#define ID_TDES           96 /* Triple Data Encryption System (TDES) */
#define ID_TRNG           97 /* True Random Number Generator (TRNG) */
#define ID_TZAESB_NS      98 /* TZAESB Non-Secure (Clocks & Interrupt) */
#define ID_TZAESB_NS_SINT 99 /* TZAESB Non-Secure (Interrupt only) */
#define ID_TZAESB_S      100 /* TZAESB Secure */
#define ID_TZAESB_S_SINT 101 /* TZAESB Secure (Interrupt only) */
#define ID_TZC           102 /* TrustZone Address Space Controller (TZC400) */
#define ID_TZPM          103 /* TrustZone Peripheral Manager (TZPM) */
#define ID_UDPHSA        104 /* USB Device High Speed A (UDPHSA) */
#define ID_UDPHSB        105 /* USB Device High Speed B (UDPHSB) */
#define ID_UHPHS         106 /* USB Host Controller High Speed (UHPHS) */
#define ID_XDMAC0_SINT   112 /* DMA 0, mem to periph, 32 CH, Secure INT */
#define ID_XDMAC1_SINT   113 /* DMA 1, mem to periph, 32 CH, Secure INT */
#define ID_XDMAC2_SINT   114 /* DMA 2, mem to mem, 4 Channels, Secure INT */
#define ID_AES_SINT      115 /* Advanced Encryption Standard, Secure INT */
#define ID_GMAC0_Q1      116 /* GMAC0 Queue 1 */
#define ID_GMAC0_Q2      117 /* GMAC0 Queue 2 */
#define ID_GMAC0_Q3      118 /* GMAC0 Queue 3 */
#define ID_GMAC0_Q4      119 /* GMAC0 Queue 4 */
#define ID_GMAC0_Q5      120 /* GMAC0 Queue 5 */
#define ID_GMAC1_Q1      121 /* GMAC1 Queue 1 */
#define ID_ICM_SINT      122 /* Integrity Check Monitor, Secure INTerrupt */
#define ID_MCAN0_INT1    123 /* MCAN0 interrupt1 (MCAN0_INT1) */
#define ID_MCAN1_INT1    124 /* MCAN1 interrupt1 (MCAN1_INT1) */
#define ID_MCAN2_INT1    125 /* MCAN2 interrupt1 (MCAN2_INT1) */
#define ID_MCAN3_INT1    126 /* MCAN3 interrupt1 (MCAN3_INT1) */
#define ID_MCAN4_INT1    127 /* MCAN4 interrupt1 (MCAN4_INT1) */
#define ID_MCAN5_INT1    128 /* MCAN5 interrupt1 (MCAN5_INT1) */
#define ID_PIOA_SINT     129 /* For PIO 0 to 31, Secure INTerrupt */
#define ID_PIOB_SINT     130 /* For PIO 32 to 63, Secure INTerrupt */
#define ID_PIOC_SINT     131 /* For PIO 64 to 95, Secure INTerrupt */
#define ID_PIOD_SINT     132 /* For PIO 96 to 127, Secure INTerrupt */
#define ID_PIOE_SINT     133 /* For PIO 128 to 136, Secure INTerrupt */
#define ID_PIT64B0_SINT  135 /* 64-bit PIT 0, Secure INTerrupt */
#define ID_PIT64B1_SINT  136 /* 64-bit PIT 1, Secure INTerrupt */
#define ID_PIT64B2_SINT  137 /* 64-bit PIT 2, Secure INTerrupt */
#define ID_PIT64B3_SINT  138 /* 64-bit PIT 3, Secure INTerrupt */
#define ID_PIT64B4_SINT  139 /* 64-bit PIT 4, Secure INTerrupt */
#define ID_PIT64B5_SINT  140 /* 64-bit PIT 5, Secure INTerrupt */
#define ID_SDMMC0_TIMER  141 /* SD Host controller 0 (eMMC 5.1) Timer int */
#define ID_SDMMC1_TIMER  142 /* SD Host controller 1 (eMMC 4.51) Timer int */
#define ID_SDMMC2_TIMER  143 /* SD Host controller 2 (eMMC 4.51) Timer int */
#define ID_SHA_SINT      144 /* Secure Hash Algorithm, Secure INTerrupt */
#define ID_TC0_SINT0     145 /* 32-bit TC 0 Channel 0, Secure INTerrupt */
#define ID_TC0_SINT1     146 /* 32-bit TC 0 Channel 1, Secure INTerrupt */
#define ID_TC0_SINT2     147 /* 32-bit TC 0 Channel 2 (TC0_SINT2) */
#define ID_TC1_SINT0     148 /* 32-bit TC 1 Channel 0, Secure INTerrupt */
#define ID_TC1_SINT1     149 /* 32-bit TC 1 Channel 1, Secure INTerrupt */
#define ID_TC1_SINT2     150 /* 32-bit TC 1 Channel 2, Secure INTerrupt */
#define ID_TDES_SINT     151 /* Triple Data Encryption System, Secure INT */
#define ID_TRNG_SINT     152 /* True Random Number Generator, Secure INT */
#define ID_EXT_IRQ0      153 /* External  Interrupt ID0 (FIQ) (EXT_IRQ0) */
#define ID_EXT_IRQ1      154 /* External  Interrupt ID1 (IRQ) (EXT_IRQ1) */

#define ID_PERIPH_MAX    154 /* Number of peripheral IDs */

/* ************************************************************************** */
/*   BASE ADDRESS DEFINITIONS FOR SAMA7G54                                    */
/* ************************************************************************** */
#define ACC_BASE_ADDRESS                 0xe1600000
#define ADC_BASE_ADDRESS                 0xe1000000
#define AES_BASE_ADDRESS                 0xe1810000
#define ASRC_BASE_ADDRESS                0xe1610000
#define BSC_BASE_ADDRESS                 0xe001d054
#define CHIPID_BASE_ADDRESS              0xe0020000
#define CSI_BASE_ADDRESS                 0xe1400000
#define CPKCC_BASE_ADDRESS               0xe000c000
#define CSI2DC_BASE_ADDRESS              0xe1404000
#define DDRPUBL_BASE_ADDRESS             0xe3804000
#define DWDT_BASE_ADDRESS                0xe001c000
#define EIC_BASE_ADDRESS                 0xe1628000
#define FLEXCOM0_BASE_ADDRESS            0xe1818000
#define FLEXCOM1_BASE_ADDRESS            0xe181c000
#define FLEXCOM2_BASE_ADDRESS            0xe1820000
#define FLEXCOM3_BASE_ADDRESS            0xe1824000
#define FLEXCOM4_BASE_ADDRESS            0xe2018000
#define FLEXCOM5_BASE_ADDRESS            0xe201c000
#define FLEXCOM6_BASE_ADDRESS            0xe2020000
#define FLEXCOM7_BASE_ADDRESS            0xe2024000
#define FLEXCOM8_BASE_ADDRESS            0xe2818000
#define FLEXCOM9_BASE_ADDRESS            0xe281c000
#define FLEXCOM10_BASE_ADDRESS           0xe2820000
#define FLEXCOM11_BASE_ADDRESS           0xe2824000
#define GMAC0_BASE_ADDRESS               0xe2800000
#define GMAC1_BASE_ADDRESS               0xe2804000
#define GPBR_BASE_ADDRESS                0xe001d060
#define I2SMCC0_BASE_ADDRESS             0xe161c000
#define I2SMCC1_BASE_ADDRESS             0xe1620000
#define ICM_BASE_ADDRESS                 0xe081c000
#define ISC_BASE_ADDRESS                 0xe1408000
#define MATRIX_BASE_ADDRESS              0xe0804000
#define MCAN0_BASE_ADDRESS               0xe0828000
#define MCAN1_BASE_ADDRESS               0xe082c000
#define MCAN2_BASE_ADDRESS               0xe0830000
#define MCAN3_BASE_ADDRESS               0xe0834000
#define MCAN4_BASE_ADDRESS               0xe0838000
#define MCAN5_BASE_ADDRESS               0xe083c000
#define NICGPV_BASE_ADDRESS              0xe8b00000
#define OTPC_BASE_ADDRESS                0xe8c00000
#define PDMC0_BASE_ADDRESS               0xe1608000
#define PDMC1_BASE_ADDRESS               0xe160c000
#define PIO_BASE_ADDRESS                 0xe0014000
#define PIT64B0_BASE_ADDRESS             0xe1800000
#define PIT64B1_BASE_ADDRESS             0xe1804000
#define PIT64B2_BASE_ADDRESS             0xe1808000
#define PIT64B3_BASE_ADDRESS             0xe2004000
#define PIT64B4_BASE_ADDRESS             0xe2008000
#define PIT64B5_BASE_ADDRESS             0xe2810000
#define PMC_BASE_ADDRESS                 0xe0018000
#define PWM_BASE_ADDRESS                 0xe1604000
#define QSPI0_BASE_ADDRESS               0xe080c000
#define QSPI1_BASE_ADDRESS               0xe0810000
#define RSTC_BASE_ADDRESS                0xe001d000
#define RTC_BASE_ADDRESS                 0xe001d0a8
#define RTT_BASE_ADDRESS                 0xe001d020
#define SCKC_BASE_ADDRESS                0xe001d050
#define SDMMC0_BASE_ADDRESS              0xe1204000
#define SDMMC1_BASE_ADDRESS              0xe1208000
#define SDMMC2_BASE_ADDRESS              0xe120c000
#define SECUMOD_BASE_ADDRESS             0xe0004000
#define SFR_BASE_ADDRESS                 0xe1624000
#define SFRBU_BASE_ADDRESS               0xe0008000
#define SHA_BASE_ADDRESS                 0xe1814000
#define SHDWC_BASE_ADDRESS               0xe001d010
#define HSMC_BASE_ADDRESS                0xe0808000
#define SPDIFRX_BASE_ADDRESS             0xe1614000
#define SPDIFTX_BASE_ADDRESS             0xe1618000
#define SSC0_BASE_ADDRESS                0xe180c000
#define SSC1_BASE_ADDRESS                0xe200c000
#define SYSCWP_BASE_ADDRESS              0xe001d0dc
#define TC0_BASE_ADDRESS                 0xe2814000
#define TC1_BASE_ADDRESS                 0xe0800000
#define TCPCA_BASE_ADDRESS               0xe0840000
#define TCPCB_BASE_ADDRESS               0xe0844000
#define TDES_BASE_ADDRESS                0xe2014000
#define TRNG_BASE_ADDRESS                0xe2010000
#define TZAESBNS_BASE_ADDRESS            0xe0820000
#define TZAESBS_BASE_ADDRESS             0xe0824000
#define TZAESBASC_BASE_ADDRESS           0xe2000000
#define TZC_BASE_ADDRESS                 0xe3000000
#define TZPM_BASE_ADDRESS                0xe0010000
#define DDRUMCTL_BASE_ADDRESS            0xe3800000
#define UDPHSA_BASE_ADDRESS              0xe0814000
#define UDPHSB_BASE_ADDRESS              0xe0818000
#define UHPHS_OHCI_BASE_ADDRESS          0x00400000
#define UHPHS_EHCI_BASE_ADDRESS          0x00500000
#define XDMAC0_BASE_ADDRESS              0xe2808000
#define XDMAC1_BASE_ADDRESS              0xe280c000
#define XDMAC2_BASE_ADDRESS              0xe1200000

/* ************************************************************************** */
/*   MEMORY MAPPING DEFINITIONS FOR SAMA7G54                                  */
/* ************************************************************************** */
#define IROM_SIZE                      0x00014000
#define ECC_ROM_SIZE                   0x00018000
#define CPKCC_ROM_SIZE                 0x00010000
#define CPKCC_RAM_SIZE                 0x00001000
#define IRAM_SIZE                      0x00020000
#define UDPHS_RAMA_SIZE                0x00100000
#define UDPHS_RAMB_SIZE                0x00100000
#define UHPHS_OHCI_SIZE                0x00001000
#define UHPHS_EHCI_SIZE                0x00100000
#define NFC_RAM_SIZE                   0x00003000
#define NFC_SIZE                       0x08000000
#define QSPIMEM0_SIZE                  0x10000000
#define QSPIMEM1_SIZE                  0x10000000
#define EBI_CS0_SIZE                   0x08000000
#define EBI_CS1_SIZE                   0x08000000
#define EBI_CS2_SIZE                   0x08000000
#define EBI_CS3_SIZE                   0x08000000
#define DDR_CS_SIZE                    0x80000000
#define SECURAM_SIZE                   0x00004000
#define SDMMC0_SIZE                    0x00004000
#define SDMMC1_SIZE                    0x00004000
#define SDMMC2_SIZE                    0x00004000
#define APB_DBG_S_SIZE                 0x00060000
#define APB_DBG_SIZE                   0x00001000
#define NICGPV_SIZE                    0x00100000
#define OTPC_SIZE                      0x00001000
#define CSI2DC_META_SIZE               0x00002000
#define ARM_PERIPH_SIZE                0x00008000
#define PERIPHERALS_SIZE               0x10000000

#define IROM_ADDR                      0x00000000
#define ECC_ROM_ADDR                   0x00020000
#define CPKCC_ROM_ADDR                 0x00040000
#define CPKCC_RAM_ADDR                 0x00051000
#define IRAM_ADDR                      0x00100000
#define UDPHS_RAMA_ADDR                0x00200000
#define UDPHS_RAMB_ADDR                0x00300000
#define UHPHS_OHCI_ADDR                0x00400000
#define UHPHS_EHCI_ADDR                0x00500000
#define NFC_RAM_ADDR                   0x00600000
#define NFC_ADDR                       0x10000000
#define QSPIMEM0_ADDR                  0x20000000
#define QSPIMEM1_ADDR                  0x30000000
#define EBI_CS0_ADDR                   0x40000000
#define EBI_CS1_ADDR                   0x48000000
#define EBI_CS2_ADDR                   0x50000000
#define EBI_CS3_ADDR                   0x58000000
#define DDR_CS_ADDR                    0x60000000
#define SECURAM_ADDR                   0xe0000000
#define SDMMC0_ADDR                    0xe1204000
#define SDMMC1_ADDR                    0xe1208000
#define SDMMC2_ADDR                    0xe120c000
#define APB_DBG_S_ADDR                 0xe8800000
#define APB_DBG_ADDR                   0xe8900000
#define NICGPV_ADDR                    0xe8b00000
#define OTPC_ADDR                      0xe8c00000
#define CSI2DC_META_ADDR               0xe8c02000
#define ARM_PERIPH_ADDR                0xe8c10000
#define PERIPHERALS_ADDR               0xe0000000

/* ************************************************************************** */
/*   DEVICE SIGNATURES FOR SAMA7G54                                           */
/* ************************************************************************** */
#define CHIP_JTAGID                    0X05B4203F
#define CHIP_CIDR                      0X80162110
#define CHIP_EXID                      0X00000000

#endif /* _SAMA7G54_H_ */

