/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef __VIRTIO_BE_PRIVATE_H
#define __VIRTIO_BE_PRIVATE_H

#include <drivers/virtio_be.h>
#include <drivers/virtio_ring.h>
#include <kernel/mutex.h>
#include <sys/queue.h>

/* Private copy of one descriptor buffer range and its pinned mapping. */
struct virtio_be_segment {
	struct virtio_mem_region mapping;
	uint64_t address;
	uint32_t size;
	bool writable;
	bool pinned;
};

struct virtio_be_cursor {
	uint16_t segment;
	size_t offset;
};

struct virtio_be_request {
	struct virtio_be_segment *segments;
	/* Number of segments in the current chain. */
	uint16_t count;
	uint64_t readable_remaining;
	uint64_t writable_remaining;
	uint32_t written;
	uint16_t head;
	struct virtio_be_cursor read_cursor;
	struct virtio_be_cursor write_cursor;
};

/* Backend split-ring mappings and states. */
struct virtqueue_be_split_ring {
	struct vring_split_regions regions;
	/* Available entries consumed by the backend. */
	uint16_t last_avail_idx;
	/* Used entries published by the backend. */
	uint16_t last_used_idx;
};

struct virtqueue_be {
	struct virtio_be_dev *vbe_dev;
	struct virtqueue_be_split_ring split_ring;
	/* Reusable request borrowed by the class under the queue mutex. */
	struct virtio_be_request request;
	uint16_t qid;
	uint16_t size;
	bool running;
	/* Send a used-buffer hint, or NULL when the peer polls this queue. */
	TEE_Result (*notify)(struct virtqueue_be *vq);
	/* Serializes ring and request operations. */
	struct mutex mutex;
};

static inline void virtqueue_be_init(struct virtqueue_be *vq,
				     struct virtio_be_dev *vbe_dev,
				     uint16_t qid)
{
	*vq = (struct virtqueue_be){
		.vbe_dev = vbe_dev,
		.qid = qid,
	};
	mutex_init(&vq->mutex);
}

static inline void virtqueue_be_deinit(struct virtqueue_be *vq)
{
	mutex_destroy(&vq->mutex);
}

#define virtio_be_for_each_queue(vbe_dev, qid) \
	for ((qid) = 0; (qid) < (vbe_dev)->type->queue_count; (qid)++)

static inline TEE_Result
virtio_be_dev_map_region(struct virtio_be_dev *vbe_dev,
			 uint64_t address, size_t size, size_t alignment,
			 enum virtio_memory_access access,
			 struct virtio_mem_region *mapping)
{
	return vbe_dev->ops->pin(vbe_dev, address, size, alignment, access,
				 mapping);
}

static inline void
virtio_be_dev_unmap_region(struct virtio_be_dev *vbe_dev,
			   struct virtio_mem_region *mapping)
{
	vbe_dev->ops->release(vbe_dev, mapping);
}

TEE_Result
virtqueue_be_bind(struct virtqueue_be *vq,
		  const struct virtio_queue_config *qinfo);
void virtqueue_be_unbind(struct virtqueue_be *vq);

/* Atomically set DEVICE_NEEDS_RESET; does not acquire the device mutex. */
void virtio_be_dev_needs_reset(struct virtio_be_dev *vbe_dev);
/* Check whether new work is allowed; caller holds the queue mutex. */
bool virtqueue_be_running(struct virtqueue_be *vq);

#endif /* __VIRTIO_BE_PRIVATE_H */
