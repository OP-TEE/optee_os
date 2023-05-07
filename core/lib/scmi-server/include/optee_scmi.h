/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2019-2022, Linaro Limited
 */
#ifndef OPTEE_SCMI_H
#define OPTEE_SCMI_H

#include <tee_api_types.h>
#include <types_ext.h>

/*
 * Return virtual address mapped for target SMT IOMEM address range
 *
 * @pa: Target address range base physical address
 * @sz: Target address range byte size
 * @shmem_is_secure: True if memory is secure, false otherwise
 * Return a virtual address or 0 is memory is not mapped
 */
uintptr_t smt_phys_to_virt(uintptr_t pa, size_t sz, bool shmem_is_secure);

#endif /* OPTEE_SCMI_H */
