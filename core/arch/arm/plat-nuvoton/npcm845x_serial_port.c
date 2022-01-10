/*
 * Copyright (c) 2015-2018, ARM Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdbool.h>

#include <arch.h>
#include <arch_helpers.h>
#include <common/debug.h>
#include <drivers/arm/gicv2.h>
#include <drivers/delay_timer.h>
#include <drivers/generic_delay_timer.h>
#include <lib/mmio.h>
#include <lib/psci/psci.h>

#include <plat_npcm845x.h>
#include <sci/sci.h>

#include <npcm845x_pads.h>
#include <npcm845x_iomux.h>
#include <npcm845x_lpuart.h>
#include <npcm845x_clock.h>
#include <npcm845x_gcr.h>




uintptr_t npcm850_get_base_uart(UART_DEV_T devNum)
{
	
	return (uintptr_t)0xF0000000 + devNum * 0x1000;
}

uintptr_t npcm850_get_base_clk()
{
	
	return (uintptr_t)0xF0801000;
}

uintptr_t npcm850_get_base_gcr()
{
	
	return (uintptr_t)0xF0800000;
}
void npcm850_wait_for_empty(int uart_n)
	{
		volatile struct npcmX50_uart *uart = ( struct npcmX50_uart *)(uintptr_t)npcm850_get_base_uart(uart_n);
		
		//volatile uint32_t temp = &uart->lsr;
		
		while((*(uint8_t *)(uintptr_t)(&uart->lsr) & 0x40) == 0x00)
		{
			// wait for THRE (Transmitter Holding Register Empty) and TSR (Transmitter Shift Register) to be empty.
		// some delay. notice needed some delay so UartUpdateTool will pass w/o error log
			
		}
		volatile unsigned int delay;
		for (delay = 0; delay < 10000; delay++);
			
	}
	
	
int UART_Init (UART_DEV_T devNum,  UART_BAUDRATE_T baudRate)
{
	uint32_t val = 0;
	uint32_t clk_base = npcm850_get_base_clk();
	uint32_t gcr_base =  npcm850_get_base_gcr();
	uint32_t uart_base = npcm850_get_base_uart(devNum);
	volatile struct npcmX50_uart *uart =  (struct npcmX50_uart *)(uintptr_t)uart_base;
	// Use  CLKREF to be idependant of CPU frequency
	
	volatile struct clk_ctl *clk_ctl_obj = ( struct clk_ctl *)(uintptr_t)clk_base;
	volatile struct npcm850_gcr *gcr_ctl_obj = (struct npcm850_gcr *)(uintptr_t)gcr_base;
	// Clear bits 8/9
	//mmio_write_32(clk_ctl_obj->clksel,(mmio_read_32(clk_ctl_obj->clksel) & ~((uint32_t)0x3<<8)));
	clk_ctl_obj->clksel = clk_ctl_obj->clksel & ~((uint32_t)0x3<<8);
	// set value b10 - for CLKREF
	//mmio_write_32(clk_ctl_obj->clksel ,(mmio_read_32((clk_ctl_obj->clksel) | (uint32_t)0x2<<8)));
	clk_ctl_obj->clksel = clk_ctl_obj->clksel | ((uint32_t)0x2<<8);
	// Set devider according to baudrate 
	// clear bits 16-20
	//mmio_write_32(clk_ctl_obj->clkdiv1 , (mmio_read_32(clk_ctl_obj->clkdiv1) & ~((uint32_t)0x1F<<16)));
	clk_ctl_obj->clkdiv1 = clk_ctl_obj->clkdiv1 & ~((uint32_t)0x1F<<16);
	// clear bits 11-15 - set value 0
	if (devNum == 3)
	{
		clk_ctl_obj->clkdiv2 = clk_ctl_obj->clkdiv2 & ~((uint32_t)0x1F<<11);
	}
	
		
	npcm850_wait_for_empty(devNum);
	
		
	val = LCR_WLS_8bit;
	//*(volatile uint8_t *)(uintptr_t)(&uart->lcr) = val;
	mmio_write_8((uint64_t)&uart->lcr,val);
	
	// disable all interrupts	
	mmio_write_8((uint64_t)&uart->ier , 0); 
	
	/*
	* Set the RX FIFO trigger level, reset RX, TX FIFO
	*/
	val = FCR_FME | FCR_RFR | FCR_TFR | FCR_RFITL_4B;
	mmio_write_8((uint64_t)(&uart->fcr) , val); // reset TX and RX FIFO


	
	
	/*
	* Set port for 8 bit, 1 stop, no parity
	*/
	val = LCR_WLS_8bit;
	val |= 0x80; // Set DLAB bit; Accesses the Divisor Latch Registers (DLL, DLM).
	mmio_write_8((uint64_t)(&uart->lcr),val);
	
	
	// Baud Rate = UART Clock 24MHz / (16 * (11+2)) = 115384
	mmio_write_8((uint64_t)(&uart->dll)  ,  11); 
	mmio_write_8((uint64_t)(&uart->dlm ), 0x00);	
		
	val = mmio_read_8((uint64_t)&uart->lcr);
	val &= (0x7F); // Clear DLAB bit; Accesses RBR, THR or IER registers.
	mmio_write_8((uint64_t)(&uart->lcr), val);	
	
	if (devNum == 0)
	{
		gcr_ctl_obj->mfsel4 &= ~((uint32_t)1 << 1);
		gcr_ctl_obj->mfsel1 |= (uint32_t)1<<9;
		
		/*
		val = mmio_read_32(gcr_ctl_obj->mfsel4);
		val &= ~((uint32_t)1 << 1);   // BSPASEL (BMC Serial Port Alternate Port Select). GPO48/TXD2 and GPIO49/RXD2 are selected (default).
		mmio_write_32(gcr_ctl_obj->mfsel4,val);
		
		// Set BU0 Mux pins
		val = mmio_read_32(gcr_ctl_obj->mfsel1);
		val |= (uint32_t)1<<9;		 // Selects Core Serial Port 0 or GPIO option. If this bit is set, MFSEL6 bits 1 	and 31 must be set to 0. 0: GPIO41 and GPIO42 selected
		mmio_write_32(gcr_ctl_obj->mfsel1,val);
		*/
	}
	else if (devNum == 3)
	{
		
		// Pin Mux 
		gcr_ctl_obj->mfsel4 &= ~((uint32_t)1 << 1);
		gcr_ctl_obj->mfsel1 |= (uint32_t)1<<11;
		gcr_ctl_obj->spswc &= ((uint32_t)7 << 0);
		gcr_ctl_obj->spswc |= ((uint32_t)2 << 0);
		/*
		val = mmio_read_32(gcr_ctl_obj->mfsel4);
		val &= ~((uint32_t)1 << 1);   // BSPASEL (BMC Serial Port Alternate Port Select). GPO48/TXD2 and GPIO49/RXD2 are selected (default).
		mmio_write_32(gcr_ctl_obj->mfsel4,val);
		
		// Set SI2 Mux pins
		val = mmio_read_32(gcr_ctl_obj->mfsel1);
		val |= (uint32_t)1<<11; // HSI2SEL (Host Serial Interface 2 Select). TXD2, RXD2, nCTS2, nRTS2, nDCD2, nDTR2_BOUT2, nDSR2 and nRI2 selected.
		mmio_write_32(gcr_ctl_obj->mfsel1,val);

		// Set UART3 output to SI2
		val = mmio_read_32(gcr_ctl_obj->spswc);
		val &= ((uint32_t)7 << 0);// clear bits 2-0
		val |= ((uint32_t)2 << 0);// Mode uart_n - Host SP1 connected to BMC UART1, Host SP2 connected to BMC UART2, BMC UART3 connected to Serial Interface 2
		mmio_write_32(gcr_ctl_obj->spswc,val);
		*/
		
		
	}
	else
	{
		// Not used! For debug - halt!
		while(1);
	}
	return 0;
	
}

