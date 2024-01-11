/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2022, Microchip
 */

#ifndef __DRIVERS_I2C_H
#define __DRIVERS_I2C_H

#include <kernel/dt_driver.h>
#include <libfdt.h>
#include <tee_api_types.h>

/**
 * DEFINE_I2C_DEV_DRIVER - Declare an I2C driver
 *
 * @__name: I2C device driver name
 * @__match_table: match table associated to the driver
 * @__i2c_probe: I2C probe function with the following prototype:
 *	TEE_Result (*probe)(struct i2c_dev *i2c_dev, const void *fdt,
 *			    int node, const void *compat_data);
 */
#define DEFINE_I2C_DEV_DRIVER(__name, __match_table, __i2c_probe) \
	static TEE_Result __name ## _probe_i2c_dev(const void *fdt, int node, \
						   const void *compat_data) \
	{ \
		struct i2c_dev *i2c_dev = NULL; \
		TEE_Result res = TEE_ERROR_GENERIC; \
		\
		res = i2c_dt_get_dev(fdt, node, &i2c_dev); \
		if (res) \
			return res; \
		return __i2c_probe(i2c_dev, fdt, node, compat_data); \
	} \
	DEFINE_DT_DRIVER(__name ## _dt_driver) = { \
		.name = # __name, \
		.type = DT_DRIVER_I2C, \
		.match_table = __match_table, \
		.probe = __name ## _probe_i2c_dev, \
	}

#define I2C_SMBUS_MAX_BUF_SIZE	32

enum i2c_smbus_dir {
	I2C_SMBUS_READ,
	I2C_SMBUS_WRITE,
};

enum i2c_smbus_protocol {
	I2C_SMBUS_PROTO_BYTE,
	/*
	 * Like block but does not insert "count" in sent data, useful for
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
 */
struct i2c_dev {
	struct i2c_ctrl *ctrl;
	uint16_t addr;
};

/**
 * struct i2c_ctrl_ops - Operations provided by I2C controller drivers
 *
 * @read: I2C read operation
 * @write: I2C write operation
 * @smbus: SMBus protocol operation
 */
struct i2c_ctrl_ops {
	TEE_Result (*read)(struct i2c_dev *i2c_dev, uint8_t *buf, size_t len);
	TEE_Result (*write)(struct i2c_dev *i2c_dev, const uint8_t *buf,
			    size_t len);
	TEE_Result (*smbus)(struct i2c_dev *i2c_dev, enum i2c_smbus_dir dir,
			    enum i2c_smbus_protocol proto, uint8_t cmd_code,
			    uint8_t *buf, size_t len);
};

/**
 * struct i2c_ctrl - I2C controller
 *
 * @ops: Operations associated to the I2C controller
 */
struct i2c_ctrl {
	const struct i2c_ctrl_ops *ops;
};

#ifdef CFG_DRIVERS_I2C
/**
 * i2c_create_dev - Create and i2c_dev struct from device-tree
 *
 * @i2c_ctrl: Controller to be used with this device
 * @fdt: Device-tree to work on
 * @node: Node to work on in @fdt provided device-tree
 *
 * Return an i2c_dev struct filled from device-tree description
 */
struct i2c_dev *i2c_create_dev(struct i2c_ctrl *i2c_ctrl, const void *fdt,
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
				   size_t len)
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
				  size_t len)
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
static inline TEE_Result i2c_smbus_raw(struct i2c_dev *i2c_dev,
				       enum i2c_smbus_dir dir,
				       enum i2c_smbus_protocol proto,
				       uint8_t cmd_code, uint8_t *buf,
				       size_t len)
{
	if (!i2c_dev->ctrl->ops->smbus)
		return TEE_ERROR_NOT_SUPPORTED;

	if (len > I2C_SMBUS_MAX_BUF_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;

	return i2c_dev->ctrl->ops->smbus(i2c_dev, dir, proto, cmd_code, buf,
					 len);
}

/**
 * i2c_dt_get_dev - Get an I2C device from a DT node
 *
 * @fdt: Device tree to work on
 * @nodeoffset: Node offset of the I2C bus consumer
 * @i2c_dev: Output I2C bus device upon success
 *
 * Return TEE_SUCCESS in case of success
 * Return TEE_ERROR_DEFER_DRIVER_INIT if I2C controller is not initialized
 * Return TEE_ERROR_ITEM_NOT_FOUND if the I2C controller node does not exist
 * Return a TEE_Result compliant code in case of error
 */
static inline TEE_Result i2c_dt_get_dev(const void *fdt, int nodeoffset,
					struct i2c_dev **out_i2c_dev)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	void *i2c_dev = NULL;

	res = dt_driver_device_from_parent(fdt, nodeoffset, DT_DRIVER_I2C,
					   &i2c_dev);
	if (!res)
		*out_i2c_dev = i2c_dev;

	return res;
}
#else
static inline TEE_Result i2c_write(struct i2c_dev *i2c_dev __unused,
				   const uint8_t *buf __unused,
				   size_t len __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}

static inline TEE_Result i2c_read(struct i2c_dev *i2c_dev __unused,
				  uint8_t *buf __unused, size_t len __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}

static inline TEE_Result i2c_smbus_raw(struct i2c_dev *i2c_dev __unused,
				       enum i2c_smbus_dir dir __unused,
				       enum i2c_smbus_protocol proto __unused,
				       uint8_t cmd_code __unused,
				       uint8_t *buf __unused,
				       size_t len __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}

static inline TEE_Result i2c_dt_get_dev(const void *fdt __unused,
					int nodeoffset __unused,
					struct i2c_dev **i2c_dev __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}
#endif

/**
 * i2c_dt_get_func - Typedef of function to get I2C bus device from
 * devicetree properties
 *
 * @args: Pointer to devicetree description of the I2C bus device to parse
 * @data: Pointer to data given at i2c_dt_register_provider() call
 * @out_device: Output pointer to I2C device upon success
 */
typedef TEE_Result (*i2c_dt_get_func)(struct dt_pargs *args, void *data,
				      struct i2c_dev **out_device);

/**
 * i2c_dt_register_provider - Register a I2C controller provider and add all the
 *	child nodes of this controller in the DT probe list.
 *
 * @fdt: Device tree to work on
 * @nodeoffset: Node offset of the I2C controller
 * @get_dt_i2c: Callback to match the I2C controller with a struct i2c
 * @data: Data which will be passed to the get_dt_i2c callback
 * Returns TEE_Result value
 */
static inline TEE_Result i2c_register_provider(const void *fdt, int nodeoffset,
					       i2c_dt_get_func get_dt_i2c,
					       void *data)
{
	int subnode = -1;
	TEE_Result res = TEE_ERROR_GENERIC;

	res = dt_driver_register_provider(fdt, nodeoffset,
					  (get_of_device_func)get_dt_i2c,
					  data, DT_DRIVER_I2C);
	if (res)
		return res;

	fdt_for_each_subnode(subnode, fdt, nodeoffset)
		dt_driver_maybe_add_probe_node(fdt, subnode);

	return TEE_SUCCESS;
}

/**
 * i2c_smbus_read_byte_data() - Execute a read byte SMBus protocol operation
 *
 * @i2c_dev: I2C device used for SMBus operation
 * @cmd_code: Command code to read
 * @byte: Returned byte value read from device
 *
 * Return a TEE_Result compliant value
 */
static inline TEE_Result i2c_smbus_read_byte_data(struct i2c_dev *i2c_dev,
						  uint8_t cmd_code,
						  uint8_t *byte)
{
	return i2c_smbus_raw(i2c_dev, I2C_SMBUS_READ, I2C_SMBUS_PROTO_BYTE,
			     cmd_code, byte, 1);
}

/**
 * i2c_smbus_write_byte_data() - Execute a write byte SMBus protocol operation
 *
 * @i2c_dev: I2C device used for SMBus operation
 * @cmd_code: Command code for write operation
 * @byte: Byte to be written to the device
 *
 * Return a TEE_Result compliant value
 */
static inline TEE_Result i2c_smbus_write_byte_data(struct i2c_dev *i2c_dev,
						   uint8_t cmd_code,
						   uint8_t byte)
{
	return i2c_smbus_raw(i2c_dev, I2C_SMBUS_WRITE, I2C_SMBUS_PROTO_BYTE,
			     cmd_code, &byte, 1);
}

/**
 * i2c_bus_read_block_raw() - Execute a non-standard SMBus raw block read.
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
static inline TEE_Result i2c_bus_read_block_raw(struct i2c_dev *i2c_dev,
						uint8_t cmd_code, uint8_t *buf,
						size_t len)
{
	return i2c_smbus_raw(i2c_dev, I2C_SMBUS_READ, I2C_SMBUS_PROTO_BLOCK_RAW,
			     cmd_code, buf, len);
}

/**
 * i2c_bus_write_block_raw() - Execute a non-standard SMBus raw block write.
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
static inline TEE_Result i2c_bus_write_block_raw(struct i2c_dev *i2c_dev,
						 uint8_t cmd_code,
						 uint8_t *buf, size_t len)
{
	return i2c_smbus_raw(i2c_dev, I2C_SMBUS_WRITE,
			     I2C_SMBUS_PROTO_BLOCK_RAW, cmd_code, buf, len);
}

#endif
