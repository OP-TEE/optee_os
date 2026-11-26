/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2023-2026, HiSilicon Technologies Co., Ltd.
 */

#ifndef __HISI_DT_H__
#define __HISI_DT_H__

#include <stdint.h>
#include <kernel/boot.h>
#include <kernel/dt.h>
#include <libfdt.h>
#include <io.h>
#include <mm/core_memprot.h>

TEE_Result set_device_info_by_dt(uintptr_t *io_base, uint32_t *io_size,
				 const char *dt_dev_match);
TEE_Result set_device_info_by_node(uintptr_t *io_base, uint32_t *io_size,
			           void *fdt, int node);
TEE_Result device_init_by_dt(TEE_Result (*device_probe)(void *fdt, int node),
			     const char *dt_dev_match);

#endif /* __HISI_DT_H__ */
