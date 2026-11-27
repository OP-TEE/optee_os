/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef __DRIVERS_VIRTIO_H
#define __DRIVERS_VIRTIO_H

/* Virtio driver-side APIs for classes, transports, devices and queues. */

#include <drivers/virtio_config.h>
#include <drivers/virtio_types.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/queue.h>
#include <tee_api_types.h>
#include <util.h>

struct virtio_device;
struct virtio_device_info;
struct virtqueue;
struct virtio_map_ops;
struct virtio_transport_ops;
struct vring_split_regions;

/* Class API: driver registration, device state and configuration. */

#define VIRTIO_VENDOR_ANY		UINT32_MAX

struct virtio_id {
	uint32_t device;
	uint32_t vendor;
};

/* Frontend class callbacks for negotiation, initialization and cleanup. */
struct virtio_driver_ops {
	/* Set up queues; call virtio_device_ready() before starting users. */
	TEE_Result (*probe)(struct virtio_device *vdev);
	/* Stop users, reset, then clean up; retain resources if reset fails. */
	TEE_Result (*remove)(struct virtio_device *vdev);
	TEE_Result (*negotiate_features)(struct virtio_device *vdev,
					 struct virtio_features *feat);
	/* Schedule config work without reentering lifecycle operations. */
	void (*config_changed)(struct virtio_device *vdev);
};

struct virtio_driver {
	const char *name;
	const struct virtio_id *ids;
	size_t num_ids;
	/* Device-specific features required for the driver to operate. */
	struct virtio_features required_features;
	/* Device-specific features selected when offered by the device. */
	struct virtio_features optional_features;
	const struct virtio_driver_ops *ops;
	/* Registry fields managed by the core under drivers_lock. */
	size_t users;
	TAILQ_ENTRY(virtio_driver) link;
};

/* Registration is synchronized; matching uses registration order. */
TEE_Result virtio_register_driver(struct virtio_driver *driver);
TEE_Result virtio_unregister_driver(struct virtio_driver *driver);

const struct virtio_device_info *
virtio_device_get_info(struct virtio_device *vdev);
/* Set DRIVER_OK during probe before using the device. */
TEE_Result virtio_device_ready(struct virtio_device *vdev);
/* Query DRIVER_OK without FAILED/NEEDS_RESET; false on transport error. */
bool virtio_device_is_ready(struct virtio_device *vdev);
/* Query negotiated features during probe or while the device is ready. */
bool virtio_has_feature(struct virtio_device *vdev, unsigned int bit);
void virtio_set_drvdata(struct virtio_device *vdev, void *data);
void *virtio_get_drvdata(struct virtio_device *vdev);
/* Confirm device reset and mark queues stopped; caller stops users first. */
TEE_Result virtio_reset_device(struct virtio_device *vdev);

TEE_Result virtio_config_read(struct virtio_device *vdev, uint32_t offset,
			      void *buffer, size_t size);
TEE_Result virtio_config_write(struct virtio_device *vdev, uint32_t offset,
			       const void *buffer, size_t size);

/* Class queue API: caller serializes access and excludes teardown. */

struct virtqueue_info {
	const char *name;
	/* Schedule completion work, or NULL for polling. */
	void (*callback)(struct virtqueue *vq);
};

struct virtio_sg {
	void *data;
	uint32_t size;
};

void virtio_release_queues(struct virtio_device *vdev);
/* Create @count queues described by @info during probe setup. */
TEE_Result virtio_setup_queues(struct virtio_device *vdev, size_t count,
			      const struct virtqueue_info *info,
			      struct virtqueue **queues);

/* Submit outgoing then incoming segments; non-NULL token, <= 2^32 bytes. */
TEE_Result
virtqueue_add_sgs(struct virtqueue *vq, const struct virtio_sg *segments,
		  size_t out_count, size_t in_count, void *token);
/* Kick driver -> device. */
TEE_Result virtqueue_kick(struct virtqueue *vq);
/* On success, return one completion from @vq in @token and @written. */
TEE_Result virtqueue_get_used(struct virtqueue *vq, void **token,
			      uint32_t *written);

/* Enable notifications and recheck; pending == true requires re-scanning. */
TEE_Result virtqueue_set_notifications(struct virtqueue *vq, bool enable,
				       bool *pending);
TEE_Result virtqueue_cancel(struct virtqueue *vq, void **token);

/* Transport API: device lifecycle, queue memory and peer notification. */

struct virtio_device_info {
	struct virtio_id id;
	size_t feature_blocks;
	size_t config_size;
};

/* Transport-owned, embeddable device; fields are managed by the core. */
struct virtio_device {
	const struct virtio_transport_ops *ops;
	const struct virtio_map_ops *map_ops;
	struct virtio_device_info info;
	struct virtio_driver *driver;
	struct virtio_features features;
	void *drvdata;
	bool probe_entered;

	TAILQ_HEAD(, virtqueue) queues;
};

/*
 * struct virtio_transport_ops - Frontend transport operations
 * @get_info: Read device identity, feature-block count and configuration size.
 * @reset: Stop peer access to driver-owned resources and reset device status.
 * @get_status: Read the device status byte.
 * @set_status: Write the device status byte.
 * @get_features: Read one 32-bit device feature block.
 * @set_features: Write one 32-bit driver feature block.
 * @get_config_generation: Read configuration generation; required for reads.
 * @read_config: Read a configuration range using supported device accesses.
 * @write_config: Write a range; failure may leave partial changes. No replay.
 * @setup_queues: Allocate queues and configure their rings on the device.
 * @release_queues: Release empty queues during probe or after confirmed reset.
 * @required_features: Required common features; the core requires VERSION_1.
 */
struct virtio_transport_ops {
	TEE_Result (*get_info)(struct virtio_device *vdev,
			       struct virtio_device_info *info);
	TEE_Result (*reset)(struct virtio_device *vdev);
	TEE_Result (*get_status)(struct virtio_device *vdev, uint8_t *status);
	TEE_Result (*set_status)(struct virtio_device *vdev, uint8_t status);
	TEE_Result (*get_features)(struct virtio_device *vdev, uint32_t block,
				   uint32_t *features);
	TEE_Result (*set_features)(struct virtio_device *vdev, uint32_t block,
				   uint32_t features);
	TEE_Result (*get_config_generation)(struct virtio_device *vdev,
					    uint32_t *generation);
	TEE_Result (*read_config)(struct virtio_device *vdev, uint32_t offset,
				  void *buffer, size_t size);
	TEE_Result (*write_config)(struct virtio_device *vdev, uint32_t offset,
				   const void *buffer, size_t size);
	TEE_Result (*setup_queues)(struct virtio_device *vdev,
				  const struct virtqueue_info *info,
				  size_t count, struct virtqueue **queues);
	void (*release_queues)(struct virtio_device *vdev);
	struct virtio_features required_features;
};

/* Initialize a transport-owned device and read its identity. */
TEE_Result virtio_device_init(struct virtio_device *vdev,
			      const struct virtio_transport_ops *ops,
			      const struct virtio_map_ops *map_ops);
/* Negotiate features, probe the class and publish DRIVER_OK. */
TEE_Result virtio_device_start(struct virtio_device *vdev);
/* Transport stops and drains queue/config event dispatch before this call. */
TEE_Result virtio_device_deinit(struct virtio_device *vdev);

/* Transport retains @vdev and excludes teardown throughout dispatch. */
void virtio_config_changed(struct virtio_device *vdev);

struct virtio_map_ops {
	/* Fill a complete region covering @size. */
	TEE_Result (*map)(struct virtio_device *vdev, void *buffer, size_t size,
			  enum virtio_memory_access access,
			  struct virtio_mem_region *mapping);
	/* Release one acquired payload mapping; cannot fail. */
	void (*release)(struct virtio_device *vdev,
			struct virtio_mem_region *mapping);
};

TEE_Result
virtqueue_create(struct virtio_device *vdev, uint16_t qid, uint16_t size,
		 const struct vring_split_regions *regions,
		 TEE_Result (*kick)(struct virtqueue *vq),
		 void (*callback)(struct virtqueue *vq),
		 struct virtqueue **vqp);
/* Destroy an empty queue during probe or after confirmed reset. */
TEE_Result virtqueue_destroy(struct virtqueue *vq);

/* Transport retains @vq and excludes teardown throughout dispatch. */
void virtqueue_handle_notification(struct virtqueue *vq);

struct virtio_device *virtqueue_get_device(struct virtqueue *vq);
uint16_t virtqueue_get_qid(struct virtqueue *vq);

#endif /* __DRIVERS_VIRTIO_H */
