/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026, Jaehun Lee */
#ifndef PTA_CORE_FUZZ_COV_H
#define PTA_CORE_FUZZ_COV_H

/* Debug-only interface. Built only with CFG_CORE_FUZZ_COVERAGE=y. */
#define PTA_CORE_FUZZ_COV_UUID { 0x2d4cb7d5, 0x1c19, 0x4b8e, \
{ 0xa8, 0x36, 0xbd, 0x39, 0x0a, 0xaf, 0xfb, 0x61 } }
#define PTA_CORE_FUZZ_COV_BEGIN 0U
#define PTA_CORE_FUZZ_COV_END 1U
#define PTA_CORE_FUZZ_COV_MAP_SIZE (16U * 1024U)

/* BEGIN: no parameters. END: one MEMREF_OUTPUT containing the full map. */
#endif /* PTA_CORE_FUZZ_COV_H */
