/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2022, Vaisala Oyj
 */

#ifndef __DRIVERS_ZYNQMP_HUK_H__
#define __DRIVERS_ZYNQMP_HUK_H__

/*
 * Query Device DNA from the device
 *
 * Note: configured as weak so that it can be replaced with implementation to
 * get read only PL Device DNA from FPGA array. This would need custom IP core
 * for access.
 *
 * Both PS and PL Device DNA's have 96 bits.
 *
 * Xilinx recommends to use PL Device DNA for device identification.
 *
 * ref:
 *
 * 71342 - Zynq UltraScale+ Device - PS DNA is not write protected and is a
 * different value than the PL DNA
 *
 * https://support.xilinx.com/s/article/71342
 *
 * @device_dna: Memory buffer to receive value of Device DNA
 * @size: length of device_dna buffer (requires buffer of 12 bytes)
 * Return a TEE_Result compliant status
 */
TEE_Result tee_zynqmp_get_device_dna(uint8_t *device_dna, size_t size);

#endif /* __DRIVERS_ZYNQMP_HUK_H__ */
