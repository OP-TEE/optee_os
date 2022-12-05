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

#ifndef __NPCMX50_GCR_H_
#define __NPCMX50_GCR_H_

//#if defined (CONFIG_TARGET_ARBEL)
#include "arbel_gcr.h"
//#else
//#error "no target board defined!"
//#endif

struct npcm850_gcr {
	unsigned int  pdid;
	unsigned int  pwron;
	unsigned int  swstrps;
	unsigned int  rsvd1[2];
	unsigned int  miscpe;
	unsigned int  spldcnt;
	unsigned int  rsvd2[1];
	unsigned int  flockr2;
	unsigned int  flockr3;
	unsigned int  rsvd3[3];
	unsigned int  a35_mode;
	unsigned int  spswc;
	unsigned int  intcr;
	unsigned int  intsr;
	unsigned int  obscr1;
	unsigned int  obsdr1;
	unsigned int  rsvd4[1];
	unsigned int  hifcr;
	unsigned int  rsvd5[3];
	unsigned int  intcr2;
	unsigned int  rsvd6[1];
	unsigned int  srcnt;
	unsigned int  ressr;
	unsigned int  rlockr1;
	unsigned int  flockr1;
	unsigned int  dscnt;
	unsigned int  mdlr;
	unsigned int  scrpad_c;
	unsigned int  scrpad_b;
	unsigned int  rsvd7[4];
	unsigned int  daclvlr;
	unsigned int  intcr3;
	unsigned int  pcirctl;
	unsigned int  rsvd8[2];
	unsigned int  vsintr;
	unsigned int  rsvd9[1];
	unsigned int  sd2sur1;
	unsigned int  sd2sur2;	
	unsigned int  sd2irv3;
	unsigned int  intcr4;
	unsigned int  obscr2;
	unsigned int  obsdr2;
	unsigned int  rsvd10[5];
	unsigned int  i2csegsel;
	unsigned int  i2csegctl;
	unsigned int  vsrcr;
	unsigned int  mlockr;
	unsigned int  rsvd11[8];
	unsigned int  etsr;
	unsigned int  dft1r;
	unsigned int  dft2r;
	unsigned int  dft3r;
	unsigned int  edffsr;
	unsigned int  rsvd12[1];
	unsigned int  intcrpce3;
	unsigned int  intcrpce2;
	unsigned int  intcrpce0;
	unsigned int  intcrpce1;
	unsigned int  dactest;
	unsigned int  scrpad;
	unsigned int  usb1phyctl;
	unsigned int  usb2phyctl;
	unsigned int  usb3phyctl;
	unsigned int  intsr2;
	unsigned int  intcrpce2b;
	unsigned int  intcrpce0b;
	unsigned int  intcrpce1b;
	unsigned int  intcrpce3b;
	unsigned int  rsvd13[4];	
	unsigned int  intcrpce2c;
	unsigned int  intcrpce0c;
	unsigned int  intcrpce1c;
	unsigned int  intcrpce3c;	
	unsigned int  rsvd14[40];
	unsigned int  sd2irv4;
	unsigned int  sd2irv5;
	unsigned int  sd2irv6;
	unsigned int  sd2irv7;
	unsigned int  sd2irv8;
	unsigned int  sd2irv9;
	unsigned int  sd2irv10;
	unsigned int  sd2irv11;
	unsigned int  rsvd15[8];
	unsigned int  mfsel1;
	unsigned int  mfsel2;
	unsigned int  mfsel3;
	unsigned int  mfsel4;
	unsigned int  mfsel5;
	unsigned int  mfsel6;
	unsigned int  mfsel7;
	unsigned int  rsvd16[1];
	unsigned int  mfsel_lk1;
	unsigned int  mfsel_lk2;
	unsigned int  mfsel_lk3;
	unsigned int  mfsel_lk4;
	unsigned int  mfsel_lk5;
	unsigned int  mfsel_lk6;
	unsigned int  mfsel_lk7;
	unsigned int  rsvd17[1];
	unsigned int  mfsel_set1;
	unsigned int  mfsel_set2;
	unsigned int  mfsel_set3;
	unsigned int  mfsel_set4;
	unsigned int  mfsel_set5;
	unsigned int  mfsel_set6;
	unsigned int  mfsel_set7;
	unsigned int  rsvd18[1];
	unsigned int  mfsel_clr1;
	unsigned int  mfsel_clr2;
	unsigned int  mfsel_clr3;
	unsigned int  mfsel_clr4;
	unsigned int  mfsel_clr5;
	unsigned int  mfsel_clr6;
	unsigned int  mfsel_clr7;
	};

struct npcm850_gcr_cp1 {
	unsigned int  cpctl1;
	unsigned int  cp2bst1;
	unsigned int  b2cpnt1;
	unsigned int  cppctl1;
	unsigned int  cpbpntr1;
	};
	
struct npcm850_gcr_cp2 {
	unsigned int  cpctl2;
	unsigned int  cp2bst2;
	unsigned int  b2cpnt2;
	unsigned int  rsvd1[1];
	unsigned int  cpsp2;
	};

#endif
