/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/*
 * Copyright (C) 2022-2024, STMicroelectronics
 */

#ifndef _DT_BINDINGS_FIREWALL_STM32MP25_RISAB_H
#define _DT_BINDINGS_FIREWALL_STM32MP25_RISAB_H

/* RISAB control modes */
#define RIF_DDCID_DIS				0x0
#define RIF_DDCID_EN				0x1

#define RISAB_READ_LIST_SHIFT			8
#define RISAB_WRITE_LIST_SHIFT			16
#define RISAB_CFEN_SHIFT			24
#define RISAB_DPRIV_SHIFT			25
#define RISAB_SEC_SHIFT				26
#define RISAB_DCCID_SHIFT			27
#define RISAB_DCEN_SHIFT			31

#define RISABPROT(delegate_en, delegate_cid, sec, default_priv, \
		  enabled, cid_read_list, cid_write_list, cid_priv_list) \
	(((delegate_en) << RISAB_DCEN_SHIFT) | \
	 ((delegate_cid) << RISAB_DCCID_SHIFT) | \
	 ((sec) << RISAB_SEC_SHIFT) | ((default_priv) << RISAB_DPRIV_SHIFT) | \
	 ((enabled) << RISAB_CFEN_SHIFT) | \
	 ((cid_write_list) << RISAB_WRITE_LIST_SHIFT) | \
	 ((cid_read_list) << RISAB_READ_LIST_SHIFT) | (cid_priv_list))

/* RISABPROT macro masks */
#define RISAB_PLIST_MASK			GENMASK_32(7, 0)
#define RISAB_RLIST_MASK			GENMASK_32(15, 8)
#define RISAB_WLIST_MASK			GENMASK_32(23, 16)
#define RISAB_DCCID_MASK			GENMASK_32(30, 27)

#endif /* _DT_BINDINGS_FIREWALL_STM32MP25_RISAB_H */
