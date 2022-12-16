/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2022, Microchip
 */

#ifndef __DRIVERS_I2C_H
#define __DRIVERS_I2C_H

#include <kernel/dt.h>
#include <sys/queue.h>
#include <tee_api_types.h>

/**
 * DEFINE_I2C_DEV_DRIVER - Declare an I2C driver
 *
 * @__name: I2C device driver name
 * @__match_table: match table associated to the driver
 * @__probe: I2C probe function
 */
#define DEFINE_I2C_DEV_DRIVER(__name, __match_table, __probe, __type) \
	static const struct i2c_driver __name ## _i2c_driver = { \
		.probe = __probe, \
	}; \
	DEFINE_DT_DRIVER(__name ## _dt_driver) = { \
		.name = # __name, \
		.type = __type, \
		.match_table = __match_table, \
		.driver = (const void *)&__name ## _i2c_driver, \
		.probe = __i2c_probe, \
	}

#define I2C_SMBUS_MAX_BUF_SIZE	32

enum i2c_smbus_dir {
	I2C_SMBUS_READ,
	I2C_SMBUS_WRITE,
};

enum i2c_smbus_protocol {
	I2C_SMBUS_PROTO_BYTE,
	/* Like block but does not insert "count" in sent data, useful for
	 * EEPROM read for instance which is not SMBus but requires such
	 * sequence.
	 */
	I2C_SMBUS_PROTO_BLOCK_RAW,
};

struct i2c_ctrl;

/**
 * struct i2c_dev - I2C device
 *
 * @ctrl: I2C controller associated to the device
 * @addr: device address on the I2C bus
 * @priv: Private data associated to the device
 */
struct i2c_dev {
	struct i2c_ctrl *ctrl;
	uint8_t addr;
	void *priv;
};

/**
 * struct i2c_ctrl_ops - Operations provided by I2C controller drivers
 *
 * @read: I2C read operation
 * @write: I2C write operation
 * @smbus: SMBus protocol operation
 */
struct i2c_ctrl_ops {
	TEE_Result (*read)(struct i2c_dev *i2c_dev, uint8_t *buf, int len);
	TEE_Result (*write)(struct i2c_dev *i2c_dev, const uint8_t *buf,
			    int len);
	TEE_Result (*smbus)(struct i2c_dev *i2c_dev, uint8_t dir, uint8_t proto,
			    uint8_t cmd_code, uint8_t *buf, unsigned int len);
};

/**
 * struct i2c_ctrl - I2C controller
 *
 * @ops: Operations associated to the I2C controller
 * @priv: Private data associated to the controller
 * @node: Device tree node associated the controller
 * @link: Link used internally in the list of controller
 */
struct i2c_ctrl {
	const struct i2c_ctrl_ops *ops;
	void *priv;
	int node;
	SLIST_ENTRY(i2c_ctrl) link;
};

/**
 * struct i2c_driver - I2C driver
 *
 * @probe: Probe operation for I2C driver
 */
struct i2c_driver {
	TEE_Result (*probe)(struct i2c_dev *i2c_dev, const void *fdt,
			    int node, const void *compat_data);
};

#ifdef CFG_DRIVERS_I2C

/**
 * i2c_ctrl_register() - Register an I2C controller
 *
 * @i2c_ctrl: I2C controller to register
 * @fdt: Device tree used to parse I2C controller node
 * @node: I2C controller node
 *
 * Return a TEE_Result compliant value
 */
TEE_Result i2c_ctrl_register(struct i2c_ctrl *i2c_ctrl, const void *fdt,
			     int node);

/**
 * i2c_write() - Execute an I2C write on the I2C bus
 *
 * @i2c_dev: I2C device used for writing
 * @buf: Buffer of data to be written
 * @len: Length of data to be written
 *
 * Return a TEE_Result compliant value
 */
static inline TEE_Result i2c_write(struct i2c_dev *i2c_dev, const uint8_t *buf,
				   int len)
{
	if (!i2c_dev->ctrl->ops->write)
		return TEE_ERROR_NOT_SUPPORTED;

	return i2c_dev->ctrl->ops->write(i2c_dev, buf, len);
}

/**
 * i2c_read() - Execute an I2C read on the I2C bus
 *
 * @i2c_dev: I2C device used for reading
 * @buf: Buffer containing the read data
 * @len: Length of data to be read
 *
 * Return a TEE_Result compliant value
 */
static inline TEE_Result i2c_read(struct i2c_dev *i2c_dev, uint8_t *buf,
				  int len)
{
	if (!i2c_dev->ctrl->ops->read)
		return TEE_ERROR_NOT_SUPPORTED;

	return i2c_dev->ctrl->ops->read(i2c_dev, buf, len);
}

/**
 * i2c_smbus_raw() - Execute a raw SMBUS request
 *
 * @i2c_dev: I2C device used for SMBus operation
 * @dir: Direction for the SMBus transfer
 * @proto: SMBus Protocol to be executed
 * @cmd_code: Command code
 * @buf: Buffer used for read/write operation
 * @len: Length of buffer to be read/write
 *
 * Return a TEE_Result compliant value
 */
static inline TEE_Result i2c_smbus_raw(struct i2c_dev *i2c_dev, uint8_t dir,
				       uint8_t proto, uint8_t cmd_code,
				       uint8_t *buf, int len)
{
	if (!i2c_dev->ctrl->ops->smbus)
		return TEE_ERROR_NOT_SUPPORTED;

	return i2c_dev->ctrl->ops->smbus(i2c_dev, dir, proto, cmd_code, buf,
					 len);
}

/**
 * __i2c_probe() - Internal function used to wrap I2C devices probing
 *
 * @fdt: Device tree used for probing
 * @node: Device tree node used for probing
 * @compat_data: Data associated to the compatible that was matched
 * @dt_drv: dt_driver structure used for probing
 *
 * Return a TEE_Result compliant value
 */
TEE_Result __i2c_probe(const void *fdt, int node, const void *compat_data,
		       const struct dt_driver *dt_drv);

#else

static inline TEE_Result i2c_ctrl_register(struct i2c_ctrl *i2c_ctrl __unused,
					   const void *fdt __unused,
					   int node __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}

static inline TEE_Result i2c_write(struct i2c_dev *i2c_dev __unused,
				   const uint8_t *buf __unused,
				   int len __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}

static inline TEE_Result i2c_read(struct i2c_dev *i2c_dev __unused,
				  uint8_t *buf __unused, int len __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}

static inline TEE_Result i2c_smbus_raw(struct i2c_dev *i2c_dev __unused,
				       uint8_t dir __unused,
				       uint8_t proto __unused,
				       uint8_t cmd_code __unused,
				       uint8_t *buf __unused,
				       unsigned int len __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}

static inline TEE_Result __i2c_probe(const void *fdt __unused,
				     int node __unused,
				     const void *compat_data __unused,
				     const struct dt_driver *dt_drv __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}

#endif

/**
 * i2c_smbus_read_byte() - Execute a read byte SMBus protocol operation
 *
 * @i2c_dev: I2C device used for SMBus operation
 * @cmd_code: Command code to read
 * @byte: Returned byte value read from device
 *
 * Return a TEE_Result compliant value
 */
static inline TEE_Result i2c_smbus_read_byte(struct i2c_dev *i2c_dev,
					     uint8_t cmd_code, uint8_t *byte)
{
	return i2c_smbus_raw(i2c_dev, I2C_SMBUS_READ, I2C_SMBUS_PROTO_BYTE,
			     cmd_code, byte, 1);
}

/**
 * i2c_smbus_write_byte() - Execute a write byte SMBus protocol operation
 *
 * @i2c_dev: I2C device used for SMBus operation
 * @cmd_code: Command code for write operation
 * @byte: Byte to be written to the device
 *
 * Return a TEE_Result compliant value
 */
static inline TEE_Result i2c_smbus_write_byte(struct i2c_dev *i2c_dev,
					      uint8_t cmd_code, uint8_t byte)
{
	return i2c_smbus_raw(i2c_dev, I2C_SMBUS_WRITE, I2C_SMBUS_PROTO_BYTE,
			     cmd_code, &byte, 1);
}

/**
 * i2c_smbus_read_block_raw() - Execute a non-standard SMBus raw block read.
 * This does not insert the "count" of byte to be written unlike the SMBus block
 * read operation.
 *
 * @i2c_dev: I2C device used for SMBus operation
 * @cmd_code: Command code for read operation
 * @buf: Buffer of data read from device
 * @len: Length of data to be read from the device
 *
 * Return a TEE_Result compliant value
 */
static inline TEE_Result i2c_smbus_read_block_raw(struct i2c_dev *i2c_dev,
						  uint8_t cmd_code,
						  uint8_t *buf,
						  unsigned int len)
{
	return i2c_smbus_raw(i2c_dev, I2C_SMBUS_READ, I2C_SMBUS_PROTO_BLOCK_RAW,
			     cmd_code, buf, len);
}

/**
 * i2c_smbus_write_block_raw() - Execute a non-standard SMBus raw block write.
 * This does not insert the "count" of byte to be written unlike the SMBus block
 * write operation.
 *
 * @i2c_dev: I2C device used for SMBus operation
 * @cmd_code: Command code for write operation
 * @buf: Buffer of data to be written to the device
 * @len: Length of data to be written to the device
 *
 * Return a TEE_Result compliant value
 */
static inline TEE_Result i2c_smbus_write_block_raw(struct i2c_dev *i2c_dev,
						   uint8_t cmd_code,
						   uint8_t *buf,
						   unsigned int len)
{
	return i2c_smbus_raw(i2c_dev, I2C_SMBUS_WRITE,
			     I2C_SMBUS_PROTO_BLOCK_RAW, cmd_code, buf, len);
}

#endif
