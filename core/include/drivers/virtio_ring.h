/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef __DRIVERS_VIRTIO_RING_H
#define __DRIVERS_VIRTIO_RING_H

#include <assert.h>
#include <drivers/virtio_types.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <tee_api_types.h>
#include <util.h>

#if defined(ARM32) || defined(ARM64)
#include <arm.h>
#elif defined(RV32) || defined(RV64)
#include <riscv.h>
#else
#error Unsupported Virtio barrier architecture
#endif

/* Specification definitions and split-ring layouts. */

#define VRING_DESC_ALIGN_SIZE		16
#define VRING_AVAIL_ALIGN_SIZE		2
#define VRING_USED_ALIGN_SIZE		4

#define VRING_MAX_SIZE			32768

struct vring_desc {
	uint64_t addr;
	uint32_t len;
#define VRING_DESC_F_NEXT		BIT32(0)
#define VRING_DESC_F_WRITE		BIT32(1)
#define VRING_DESC_F_INDIRECT		BIT32(2)
	uint16_t flags;
	uint16_t next;
};

struct vring_avail {
/* Frontend requests suppression of backend used-buffer notifications. */
#define VRING_AVAIL_F_NO_INTERRUPT	BIT32(0)
	uint16_t flags;
	uint16_t idx;
	uint16_t ring[];
	/* uint16_t used_event; if VIRTIO_F_EVENT_IDX negotiated. */
};

struct vring_used_elem {
	uint32_t id;
	uint32_t len;
};

struct vring_used {
/* Backend requests suppression of frontend available-buffer notifications. */
#define VRING_USED_F_NO_NOTIFY		BIT32(0)
	uint16_t flags;
	uint16_t idx;
	struct vring_used_elem ring[];
	/* uint16_t avail_event; if VIRTIO_F_EVENT_IDX negotiated. */
};

/* Ring access and storage helpers. */

struct vring_split_regions {
	struct virtio_mem_region desc;
	struct virtio_mem_region avail;
	struct virtio_mem_region used;
};

static inline struct vring_desc *
vring_split_get_desc(const struct vring_split_regions *regions)
{
	return regions->desc.va;
}

static inline struct vring_avail *
vring_split_get_avail(const struct vring_split_regions *regions)
{
	return regions->avail.va;
}

static inline struct vring_used *
vring_split_get_used(const struct vring_split_regions *regions)
{
	return regions->used.va;
}

/* Order coherent queue accesses across the full system. */
static inline void virtio_mb(void)
{
#if defined(ARM32) || defined(ARM64)
	dsb();
#else
	/* Fence all memory and I/O accesses. */
	mb();
#endif
}

static inline TEE_Result vring_split_sizes(size_t size, size_t *desc,
					   size_t *avail, size_t *used)
{
	if (!IS_POWER_OF_TWO(size) || size > VRING_MAX_SIZE ||
	    !desc || !avail || !used)
		return TEE_ERROR_BAD_PARAMETERS;

	*desc = sizeof(struct vring_desc) * size;
	/* Reserve event-index fields even when EVENT_IDX is not negotiated. */
	*avail = offsetof(struct vring_avail, ring[size]) + sizeof(uint16_t);
	*used = offsetof(struct vring_used, ring[size]) + sizeof(uint16_t);

	return TEE_SUCCESS;
}

#endif /* __DRIVERS_VIRTIO_RING_H */
