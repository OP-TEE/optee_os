/* SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause) */
/*
 * Copyright (c) 2017-2019, STMicroelectronics
 */

#ifndef __STM32_I2C_H
#define __STM32_I2C_H

#include <drivers/clk.h>
#include <drivers/stm32_gpio.h>
#include <kernel/dt.h>
#include <mm/core_memprot.h>
#include <stdbool.h>
#include <stdint.h>
#include <util.h>
#include <types_ext.h>

/*
 * I2C specification values as per version 6.0, 4th of April 2014 [1],
 * table 10 page 48: Characteristics of the SDA and SCL bus lines for
 * Standard, Fast, and Fast-mode Plus I2C-bus devices.
 *
 * [1] https://www.nxp.com/docs/en/user-guide/UM10204.pdf
 */
#define I2C_STANDARD_RATE	U(100000)
#define I2C_FAST_RATE		U(400000)
#define I2C_FAST_PLUS_RATE	U(1000000)

/*
 * Initialization configuration structure for the STM32 I2C bus.
 * Refer to the SoC Reference Manual for more details on configuration items.
 *
 * @dt_status: non-secure/secure status read from DT
 * @pbase: I2C interface base address
 * @reg_size: I2C interface register map size
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
 * @bus_rate: Specifies the I2C clock frequency in Hertz
 * @analog_filter: True if enabling analog filter
 * @digital_filter_coef: filter coef (below STM32_I2C_DIGITAL_FILTER_MAX)
 */
struct stm32_i2c_init_s {
	unsigned int dt_status;
	paddr_t pbase;
	size_t reg_size;
	struct clk *clock;
	bool addr_mode_10b_not_7b;
	uint32_t own_address1;
	bool dual_address_mode;
	uint32_t own_address2;
	uint32_t own_address2_masks;
	bool general_call_mode;
	bool no_stretch_mode;
	uint32_t rise_time;
	uint32_t fall_time;
	uint32_t bus_rate;
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

#define I2C_ERROR_NONE		U(0x0)
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
 * @reg_size: I2C SoC registers address map size
 * @dt_status: non-secure/secure status read from DT
 * @clock: clock ID
 * @i2c_state: Driver state ID I2C_STATE_*
 * @i2c_err: Last error code I2C_ERROR_*
 * @saved_timing: Saved timing value if already computed
 * @saved_frequency: Saved frequency value if already computed
 * @sec_cfg: I2C registers configuration storage
 * @pinctrl: PINCTRLs configuration for the I2C PINs
 * @pinctrl_count: Number of PINCTRLs elements
 */
struct i2c_handle_s {
	struct io_pa_va base;
	size_t reg_size;
	unsigned int dt_status;
	struct clk *clock;
	enum i2c_state_e i2c_state;
	uint32_t i2c_err;
	uint32_t saved_timing;
	unsigned long saved_frequency;
	struct i2c_cfg sec_cfg;
	struct stm32_pinctrl *pinctrl;
	size_t pinctrl_count;
};

/* STM32 specific defines */
#define STM32_I2C_RISE_TIME_DEFAULT		U(25)	/* ns */
#define STM32_I2C_FALL_TIME_DEFAULT		U(10)	/* ns */
#define STM32_I2C_ANALOG_FILTER_DELAY_MIN	U(50)	/* ns */
#define STM32_I2C_ANALOG_FILTER_DELAY_MAX	U(260)	/* ns */
#define STM32_I2C_DIGITAL_FILTER_MAX		U(16)

/*
 * Fill struct stm32_i2c_init_s from DT content for a given I2C node
 *
 * @fdt: Reference to DT
 * @node: Target I2C node in the DT
 * @init: Output stm32_i2c_init_s structure
 * @pinctrl: Reference to output pinctrl array
 * @pinctrl_count: Input @pinctrl array size, output expected size upon success
 * Return a TEE_Result compliant value
 */
TEE_Result stm32_i2c_get_setup_from_fdt(void *fdt, int node,
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
 * Optimized 1 byte read/write function for unpaged sequences.
 * 8-bit addressing mode / single byte transferred / use default I2C timeout.
 * Return 0 on success else a negative value
 */
int stm32_i2c_read_write_membyte(struct i2c_handle_s *hi2c, uint16_t dev_addr,
				 unsigned int mem_addr, uint8_t *p_data,
				 bool write);

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

/*
 * Return true if I2C bus is enabled for secure world only, false otherwise
 */
static inline bool i2c_is_secure(struct i2c_handle_s *hi2c)
{
	return hi2c->dt_status == DT_STATUS_OK_SEC;
}

#endif /* __STM32_I2C_H */
