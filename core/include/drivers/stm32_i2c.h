/* SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause) */
/*
 * Copyright (c) 2017-2019, STMicroelectronics
 */

#ifndef __STM32_I2C_H
#define __STM32_I2C_H

#include <drivers/stm32_gpio.h>
#include <mm/core_memprot.h>
#include <stdbool.h>
#include <stdint.h>
#include <util.h>
#include <types_ext.h>

/*
 * Initialization configuration structure for the STM32 I2C bus.
 * Refer to the SoC Reference Manual for more details on configuration items.
 *
 * @pbase: I2C interface base address
 * @clock: I2C bus/interface clock
 * @addr_mode_10b_not_7b: True if 10bit addressing mode, otherwise 7bit mode
 * @own_address1: 7-bit or 10-bit first device own address.
 * @dual_address_mode: True if enabling Dual-Addressing mode
 * @own_address2: 7-bit second device own address (Dual-Addressing mode)
 * @own_address2_masks: Acknowledge mask address (Dual-Addressing mode)
 * @general_call_mode: True if enbling General-Call mode
 * @no_stretch_mode: If enabling the No-Stretch mode
 * @rise_time: SCL clock pin rising time in nanoseconds
 * @fall_time: SCL clock pin falling time in nanoseconds
 * @speed_mode: I2C clock source frequency mode
 * @analog_filter: True if enabling analog filter
 * @digital_filter_coef: filter coef (below STM32_I2C_DIGITAL_FILTER_MAX)
 */
struct stm32_i2c_init_s {
	paddr_t pbase;
	unsigned int clock;
	bool addr_mode_10b_not_7b;
	uint32_t own_address1;
	bool dual_address_mode;
	uint32_t own_address2;
	uint32_t own_address2_masks;
	bool general_call_mode;
	bool no_stretch_mode;
	uint32_t rise_time;
	uint32_t fall_time;
	enum i2c_speed_e speed_mode;
	bool analog_filter;
	uint8_t digital_filter_coef;
};

enum i2c_state_e {
	I2C_STATE_RESET,		/* Not yet initialized */
	I2C_STATE_READY,		/* Ready for use */
	I2C_STATE_BUSY,		/* Internal process ongoing */
	I2C_STATE_BUSY_TX,	/* Data Transmission ongoing */
	I2C_STATE_BUSY_RX,	/* Data Reception ongoing */
	I2C_STATE_SUSPENDED,	/* Bus is supended */
};

enum i2c_mode_e {
	I2C_MODE_NONE,		/* No active communication */
	I2C_MODE_MASTER,		/* Communication in Master Mode */
	I2C_MODE_SLAVE,		/* Communication in Slave Mode */
	I2C_MODE_MEM,		/* Communication in Memory Mode */
};

#define I2C_ERROR_NONE		0x0
#define I2C_ERROR_BERR		BIT(0)
#define I2C_ERROR_ARLO		BIT(1)
#define I2C_ERROR_ACKF		BIT(2)
#define I2C_ERROR_OVR		BIT(3)
#define I2C_ERROR_DMA		BIT(4)
#define I2C_ERROR_TIMEOUT	BIT(5)
#define I2C_ERROR_SIZE		BIT(6)

/* I2C interface registers state */
struct i2c_cfg {
	uint32_t timingr;
	uint32_t oar1;
	uint32_t oar2;
	uint32_t cr1;
	uint32_t cr2;
};

/*
 * I2C bus device
 * @base: I2C SoC registers base address
 * @clock: clock ID
 * @i2c_state: Driver state ID I2C_STATE_*
 * @i2c_err: Last error code I2C_ERROR_*
 * @sec_cfg: I2C regsiters configuration storage
 * @pinctrl: PINCTRLs configuration for the I2C PINs
 * @pinctrl_count: Number of PINCTRLs elements
 */
struct i2c_handle_s {
	struct io_pa_va base;
	unsigned long clock;
	enum i2c_state_e i2c_state;
	uint32_t i2c_err;
	struct i2c_cfg sec_cfg;
	struct stm32_pinctrl *pinctrl;
	size_t pinctrl_count;
};

/* STM32 specific defines */
#define STM32_I2C_SPEED_DEFAULT			I2C_SPEED_STANDARD
#define STM32_I2C_RISE_TIME_DEFAULT		25	/* ns */
#define STM32_I2C_FALL_TIME_DEFAULT		10	/* ns */
#define STM32_I2C_ANALOG_FILTER_DELAY_MIN	50	/* ns */
#define STM32_I2C_ANALOG_FILTER_DELAY_MAX	260	/* ns */
#define STM32_I2C_DIGITAL_FILTER_MAX		16

/*
 * Fill struct stm32_i2c_init_s from DT content for a given I2C node
 *
 * @fdt: Reference to DT
 * @node: Target I2C node in the DT
 * @init: Output stm32_i2c_init_s structure
 * @pinctrl: Reference to output pinctrl array
 * @pinctrl_count: Input @pinctrl array size, output expected size
 * Return 0 on success else a negative value
 */
int stm32_i2c_get_setup_from_fdt(void *fdt, int node,
				 struct stm32_i2c_init_s *init,
				 struct stm32_pinctrl **pinctrl,
				 size_t *pinctrl_count);

/*
 * Initialize I2C bus handle from input configuration directives
 *
 * @hi2c: Reference to I2C bus handle structure
 * @init_data: Input stm32_i2c_init_s structure
 * Return 0 on success else a negative value
 */
int stm32_i2c_init(struct i2c_handle_s *hi2c,
		   struct stm32_i2c_init_s *init_data);

/*
 * Send a memory write request in the I2C bus
 *
 * @hi2c: Reference to I2C bus handle structure
 * @dev_addr: Target device I2C address
 * @mem_addr: Target device memory address
 * @mem_addr_size: Byte size of internal memory address
 * @p_data: Data to be written
 * @size: Byte size of the data to be written
 * @timeout_ms: Timeout value in milliseconds
 * Return 0 on success else a negative value
 */
int stm32_i2c_mem_write(struct i2c_handle_s *hi2c, uint32_t dev_addr,
			uint32_t mem_addr, uint32_t mem_addr_size,
			uint8_t *p_data, size_t size, unsigned int timeout_ms);

/*
 * Send a memory read request in the I2C bus
 *
 * @hi2c: Reference to I2C bus handle structure
 * @dev_addr: Target device I2C address
 * @mem_addr: Target device memory address
 * @mem_addr_size: Byte size of internal memory address
 * @p_data: Data to be read
 * @size: Byte size of the data to be read
 * @timeout_ms: Timeout value in milliseconds
 * Return 0 on success else a negative value
 */
int stm32_i2c_mem_read(struct i2c_handle_s *hi2c, uint32_t dev_addr,
		       uint32_t mem_addr, uint32_t mem_addr_size,
		       uint8_t *p_data, size_t size, unsigned int timeout_ms);

/*
 * Send a data buffer in master mode on the I2C bus
 *
 * @hi2c: Reference to I2C bus handle structure
 * @dev_addr: Target device I2C address
 * @p_data: Data to be sent
 * @size: Byte size of the data to be sent
 * @timeout_ms: Timeout value in milliseconds
 * Return 0 on success else a negative value
 */
int stm32_i2c_master_transmit(struct i2c_handle_s *hi2c, uint32_t dev_addr,
			      uint8_t *p_data, size_t size,
			      unsigned int timeout_ms);

/*
 * Receive a data buffer in master mode on the I2C bus
 *
 * @hi2c: Reference to I2C bus handle structure
 * @dev_addr: Target device I2C address
 * @p_data: Buffer for the received data
 * @size: Byte size of the data to be received
 * @timeout_ms: Timeout value in milliseconds
 * Return 0 on success else a negative value
 */
int stm32_i2c_master_receive(struct i2c_handle_s *hi2c, uint32_t dev_addr,
			     uint8_t *p_data, size_t size,
			     unsigned int timeout_ms);

/*
 * Check link with the I2C device
 *
 * @hi2c: Reference to I2C bus handle structure
 * @dev_addr: Target device I2C address
 * @trials: Number of attempts of I2C request
 * @timeout_ms: Timeout value in milliseconds for each I2C request
 * Return 0 on success else a negative value
 */
bool stm32_i2c_is_device_ready(struct i2c_handle_s *hi2c, uint32_t dev_addr,
			       unsigned int trials, unsigned int timeout_ms);

/*
 * Suspend I2C bus.
 * Bus owner is reponsible for calling stm32_i2c_suspend().
 *
 * @hi2c: Reference to I2C bus handle structure
 */
void stm32_i2c_suspend(struct i2c_handle_s *hi2c);

/*
 * Resume I2C bus.
 * Bus owner is reponsible for calling stm32_i2c_resume().
 *
 * @hi2c: Reference to I2C bus handle structure
 */
void stm32_i2c_resume(struct i2c_handle_s *hi2c);

#endif /* __STM32_I2C_H */
