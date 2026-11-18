/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef __DRIVERS_VIRTIO_BE_H
#define __DRIVERS_VIRTIO_BE_H

/* Virtio device-side APIs for class registration, instances and requests. */

#include <drivers/virtio_config.h>
#include <drivers/virtio_types.h>
#include <kernel/mutex.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/queue.h>
#include <tee_api_types.h>

struct virtio_be_dev;
struct virtio_be_request;
struct virtqueue_be;
struct virtio_be_transport_ops;

/* Class API: registration, callbacks, instance state and request processing. */

/*
 * struct virtio_be_ops - Device-class callbacks for a backend instance
 * @create: Initialize class state, or NULL if unneeded.
 * @destroy: Release class state after successful creation, or NULL.
 * @validate_features: Validate candidate features, or NULL to accept them.
 * @start: Prepare state, call virtio_be_dev_ready(), or NULL.
 * @stop: After successful startup, stop and release class stats, or NULL.
 * @queue_kicked: Schedule work for qid under the device mutex, or NULL.
 * @read_config: Read bytes and generation together, or NULL when unsupported.
 *               A zero-length read only queries generation.
 * @write_config: Apply a range and return generation, or NULL when unsupported.
 *                Failure must leave bytes and generation unchanged.
 */
struct virtio_be_ops {
	TEE_Result (*create)(struct virtio_be_dev *vbe_dev);
	void (*destroy)(struct virtio_be_dev *vbe_dev);
	TEE_Result (*validate_features)(struct virtio_be_dev *vbe_dev,
					const struct virtio_features *feat);
	TEE_Result (*start)(struct virtio_be_dev *vbe_dev);
	void (*stop)(struct virtio_be_dev *vbe_dev);
	void (*queue_kicked)(struct virtio_be_dev *vbe_dev, uint16_t qid);
	TEE_Result (*read_config)(struct virtio_be_dev *vbe_dev,
				  uint32_t offset, void *buffer, size_t size,
				  uint32_t *generation);
	TEE_Result (*write_config)(struct virtio_be_dev *vbe_dev,
				   uint32_t offset, const void *buffer,
				   size_t size, uint32_t *generation);
};

/* Backend class definition and registration state for independent instances. */
struct virtio_be_dev_type {
	const char *name;
	uint32_t device;
	uint32_t vendor;
	/* Features offered to the frontend; core adds common features. */
	struct virtio_features features;
	size_t config_size;
	size_t queue_count;
	size_t max_queue_size;
	const struct virtio_be_ops *ops;
	/* Registry fields managed by the core under types_lock. */
	size_t users;
	TAILQ_ENTRY(virtio_be_dev_type) link;
};

TEE_Result
virtio_be_unregister_type(struct virtio_be_dev_type *type);
/* Register a backend device class with a unique, nonempty name. */
TEE_Result virtio_be_register_type(struct virtio_be_dev_type *type);

/* Call from start(); the core already holds the device mutex. */
TEE_Result virtio_be_dev_ready(struct virtio_be_dev *vbe_dev);

/* Queue a config hint after updating class state; no device mutex required. */
void virtio_be_dev_notify_config(struct virtio_be_dev *vbe_dev);

/* Query after negotiation; caller excludes renegotiation and teardown. */
bool virtio_be_dev_has_feature(struct virtio_be_dev *vbe_dev, unsigned int bit);
/* Set class data during create; release it during destroy. */
void *virtio_be_dev_get_data(struct virtio_be_dev *vbe_dev);
void virtio_be_dev_set_data(struct virtio_be_dev *vbe_dev, void *data);

/* Return a locked, running queue. */
TEE_Result virtio_be_dev_lock_queue(struct virtio_be_dev *vbe_dev, uint16_t qid,
				    struct virtqueue_be **vqp);
/* Always, complete or cancel the request before unlocking. */
void virtqueue_be_unlock(struct virtqueue_be *vq);

/* Interrupt device -> driver. */
TEE_Result virtqueue_be_notify(struct virtqueue_be *vq);
/* Enable kicks and recheck; pending == true requires re-scanning. */
TEE_Result virtqueue_be_set_kicks(struct virtqueue_be *vq, bool enable,
				  bool *pending);

/* Get the request for one chain; ITEM_NOT_FOUND means empty. */
TEE_Result virtqueue_be_get_request(struct virtqueue_be *vq,
				    struct virtio_be_request **reqp);
TEE_Result virtio_be_request_remaining(struct virtio_be_request *req,
				       uint64_t *readable, uint64_t *writable);
/* Copy frontend input into a local buffer, advancing the read position. */
TEE_Result virtio_be_request_copy_from(struct virtio_be_request *req,
				       void *buffer, size_t size,
				       size_t *copied);
/* Copy a response into frontend buffers, advancing the write position. */
TEE_Result virtio_be_request_copy_to(struct virtio_be_request *req,
				     const void *buffer, size_t size,
				     size_t *copied);
TEE_Result virtio_be_request_complete(struct virtio_be_request **reqp);
/* Abort the request without completion and require device reset. */
TEE_Result virtio_be_request_cancel(struct virtio_be_request **reqp);

/* Transport API: peer access, instances and device configuration. */

/* Transport-owned, embeddable device; fields are managed by the core. */
struct virtio_be_dev {
	struct virtio_be_dev_type *type;
	const struct virtio_be_transport_ops *ops;
	void *data;
	struct virtqueue_be *queues;

	/* Features advertised to the frontend. */
	struct virtio_features offered;
	/* Features selected by the frontend for validation. */
	struct virtio_features candidate;
	/* Validated features accepted when FEATURES_OK is set. */
	struct virtio_features accepted;

	/* Serializes control and lifecycle; acquired before queue mutexes. */
	struct mutex mutex;
	uint32_t status;
	bool started;
};

struct virtio_be_transport_ops {
	/* Validate and pin a peer-memory range. */
	TEE_Result (*pin)(struct virtio_be_dev *vbe_dev,
			  uint64_t address, size_t size,
			  size_t alignment, enum virtio_memory_access access,
			  struct virtio_mem_region *mapping);
	/* Drop one acquired mapping reference; cannot fail. */
	void (*release)(struct virtio_be_dev *vbe_dev,
			struct virtio_mem_region *mapping);
	/* Queue a retained config event; never call the peer inline. */
	void (*notify_config)(struct virtio_be_dev *vbe_dev);
	/* Required common features in addition to VERSION_1. */
	struct virtio_features required_features;
};

/* Initialize a transport-owned device using the class selected by @name. */
TEE_Result virtio_be_dev_init(struct virtio_be_dev *vbe_dev, const char *name,
			      const struct virtio_be_transport_ops *ops);
/* Caller blocks new external calls and drains existing calls before deinit. */
TEE_Result virtio_be_dev_deinit(struct virtio_be_dev *vbe_dev);

/* Notification driver -> device. */
TEE_Result virtio_be_dev_queue_kicked(struct virtio_be_dev *vbe_dev,
				      uint16_t qid);

TEE_Result virtio_be_dev_set_status(struct virtio_be_dev *vbe_dev,
				    uint8_t status);
uint8_t virtio_be_dev_get_status(struct virtio_be_dev *vbe_dev);
TEE_Result virtio_be_dev_get_features(struct virtio_be_dev *vbe_dev,
				      uint32_t block, uint32_t *features);
TEE_Result virtio_be_dev_set_features(struct virtio_be_dev *vbe_dev,
				      uint32_t block, uint32_t features);
/* Read backend instance configuration area @offset and @size. */
TEE_Result virtio_be_dev_read_config(struct virtio_be_dev *vbe_dev,
				     uint32_t offset, void *buffer,
				     size_t size, uint32_t *generation);
TEE_Result virtio_be_dev_write_config(struct virtio_be_dev *vbe_dev,
				      uint32_t offset, const void *buffer,
				      size_t size, uint32_t *generation);

/* Bind @qid after negotiation, before startup; reset the device to unbind. */
TEE_Result
virtio_be_dev_set_queue(struct virtio_be_dev *vbe_dev, uint16_t qid,
			const struct virtio_queue_config *qinfo,
			TEE_Result (*notify)(struct virtqueue_be *vq));
TEE_Result virtio_be_dev_get_queue(struct virtio_be_dev *vbe_dev, uint16_t qid,
				   struct virtio_queue_config *qinfo,
				   size_t *max_queue_size);
struct virtio_be_dev *virtqueue_be_get_device(struct virtqueue_be *vq);
uint16_t virtqueue_be_get_qid(struct virtqueue_be *vq);

#endif /* __DRIVERS_VIRTIO_BE_H */
