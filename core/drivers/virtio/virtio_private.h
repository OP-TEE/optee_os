/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef __VIRTIO_PRIVATE_H
#define __VIRTIO_PRIVATE_H

#include <drivers/virtio.h>
#include <drivers/virtio_ring.h>
#include <sys/queue.h>

struct virtqueue_split_desc_state {
	void *token;
	uint64_t writable;
	uint16_t next;
	bool mapped;
};

/* Frontend split-ring mappings, descriptor ownership and ring indices. */
struct virtqueue_split_ring {
	struct vring_split_regions regions;
	/* Track descriptor chain links, mapping state and head tokens. */
	struct virtqueue_split_desc_state *desc_state;
	/* Payload regions retained until completion or cancellation. */
	struct virtio_mem_region *desc_regions;
	uint16_t free_head;
	uint16_t num_free;
	/* Available entries published by the frontend. */
	uint16_t last_avail_idx;
	/* Used entries consumed by the frontend. */
	uint16_t last_used_idx;
	uint16_t cancel_id;
};

struct virtqueue {
	struct virtio_device *vdev;
	struct virtqueue_split_ring split_ring;
	uint16_t qid;
	uint16_t size;
	/* Submitted requests awaiting completion or cancellation. */
	uint16_t inflight;
	/* Reset confirmed; accessed only during serialized queue teardown. */
	bool stopped;
	/* Queue error blocks normal operations until device reset. */
	bool broken;
	/* Notify the device that new buffers are available on this queue. */
	TEE_Result (*kick)(struct virtqueue *vq);
	/* Class completion callback. */
	void (*callback)(struct virtqueue *vq);
	TAILQ_ENTRY(virtqueue) link;
};

/* Check that no queue error has blocked normal operations. */
static inline bool virtqueue_is_usable(struct virtqueue *vq)
{
	return !vq->broken;
}

TEE_Result virtio_queue_detach(struct virtqueue *vq);
TEE_Result virtio_queue_attach(struct virtio_device *vdev,
			       struct virtqueue *vq);

#endif /* __VIRTIO_PRIVATE_H */
