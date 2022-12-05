/*
 *  Copyright (c) 2017 Nuvoton Technology Corp.
 *
 * See file CREDITS for list of people who contributed to this
 * project.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston,
 * MA 02111-1307 USA
 */

#ifndef __NPCMX50_CLOCK_H_
#define __NPCMX50_CLOCK_H_

//#if defined (CONFIG_TARGET_ARBEL)
#include "arbel_clock.h"
//#else
//#error "no target board defined!"
//#endif

#define EXT_CLOCK_FREQUENCY_KHZ	    25 * 1000 * 1UL
#define EXT_CLOCK_FREQUENCY_MHZ	    25
#define _1Hz_           1UL
#define _1KHz_          (1000 * _1Hz_ )
#define _1MHz_          (1000 * _1KHz_)
#define _1GHz_          (1000 * _1MHz_)

struct clk_ctl {
	unsigned int  clken1;
	unsigned int  clksel;
	unsigned int  clkdiv1;
	unsigned int  pllcon0;
	unsigned int  pllcon1;
	unsigned int  swrstr;
	unsigned char res1[0x8];
	unsigned int  ipsrst1;
	unsigned int  ipsrst2;
	unsigned int  clken2;
	unsigned int  clkdiv2;
	unsigned int  clken3;
	unsigned int  ipsrst3;
	unsigned int  wd0rcr;
	unsigned int  wd1rcr;
	unsigned int  wd2rcr;
	unsigned int  swrstc1;
	unsigned int  swrstc2;
	unsigned int  swrstc3;
	unsigned int  tiprstc;
	unsigned int  pllcon2;
	unsigned int  clkdiv3;
	unsigned int  corstc;
	unsigned int  pllcong;
	unsigned int  ahbckfi;
	unsigned int  seccnt;
	unsigned int  cntr25m;
	unsigned int  clken4;
	unsigned int  ipsrst4;
	unsigned int  busto;
	unsigned int  clkdiv4;
	unsigned int  wd0rcrb;
	unsigned int  wd1rcrb;
	unsigned int  wd2rcrb;
	unsigned int  swrstc1b;
	unsigned int  swrstc2b;
	unsigned int  swrstc3b;
	unsigned int  tiprstcb;
	unsigned int  corstcb; 
	unsigned int  ipsrstdis1;
	unsigned int  ipsrstdis2;
	unsigned int  ipsrstdis3;
	unsigned int  ipsrstdis4;
	unsigned char res2[0x10];
	unsigned int  thrtl_cnt;
};

#endif
