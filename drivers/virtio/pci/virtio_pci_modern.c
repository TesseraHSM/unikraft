/* SPDX-License-Identifier: BSD-3-Clause */
/* Copyright (c) Microsoft Corporation.
 * Licensed under the BSD-3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 */

#include <errno.h>
#include <string.h>
#include <uk/alloc.h>
#include <uk/bus/pci.h>
#include <uk/errptr.h>
#include <uk/intctlr.h>
#include <uk/intctlr/limits.h>
#include <uk/print.h>
#include <uk/sched.h>
#include <x86/mmio.h>
#include <virtio/virtio_bus.h>
#include <virtio/virtio_config.h>
#include <virtio/virtio_ids.h>
#include <virtio/virtqueue.h>

#define VIRTIO_PCI_QUEUES 64
#define VIRTIO_PCI_NO_VECTOR 0xffff
#define VIRTIO_PCI_VENDOR 0x1af4
#define VIRTIO_PCI_COMMON_MIN 56
#define VIRTIO_PCI_CAP_VENDOR 0x09
#define VIRTIO_PCI_CAP_MSIX 0x11
#define VIRTIO_PCI_CMD_MEMORY 0x0002
#define VIRTIO_PCI_CMD_MASTER 0x0004
#define VIRTIO_PCI_CMD_INTX_OFF 0x0400
#define VIRTIO_MSIX_ENABLE 0x8000
#define VIRTIO_MSIX_MASK 0x4000
#define VIRTIO_MSIX_VECTOR_MASK 1
#define VIRTIO_MSIX_ENTRY 0
#define VIRTIO_IRQ_VECTOR_BASE 32
#define VIRTIO_IRQ_VECTOR_LIMIT 0xf0

struct virtio_pci_device {
	struct virtio_dev vdev;
	struct pci_device *pdev;
	__u64 common;
	__u64 notify;
	__u64 device;
	__u32 notify_len;
	__u32 device_len;
	__u32 notify_multiplier;
	__u64 notify_addr[VIRTIO_PCI_QUEUES];
	struct virtqueue *queues[VIRTIO_PCI_QUEUES];
	__u64 msix_table;
	__u16 msix_cap;
	__u16 msix_count;
	unsigned int irq;
	int irq_registered;
	volatile int irq_enabled;
	__u64 irq_count;
	__u64 queue_irqs[VIRTIO_PCI_QUEUES];
	volatile int failed;
};

static struct uk_alloc *virtio_pci_alloc;

#define to_virtio_pci(v) __containerof(v, struct virtio_pci_device, vdev)

static int virtio_pci_handle_irq(void *arg);

static int virtio_pci_mmio(struct virtio_pci_device *d, __u64 address,
			__u64 *value, unsigned int width, int write)
{
	if (!value || (width != 1 && width != 2 && width != 4 && width != 8))
		return -EINVAL;
	if (write) {
		if (width == 1)
			*(volatile __u8 *)(__uptr)address = *value;
		else if (width == 2)
			*(volatile __u16 *)(__uptr)address = *value;
		else if (width == 4)
			*(volatile __u32 *)(__uptr)address = *value;
		else
			*(volatile __u64 *)(__uptr)address = *value;
	} else {
		if (width == 1)
			*value = *(volatile __u8 *)(__uptr)address;
		else if (width == 2)
			*value = *(volatile __u16 *)(__uptr)address;
		else if (width == 4)
			*value = *(volatile __u32 *)(__uptr)address;
		else
			*value = *(volatile __u64 *)(__uptr)address;
	}
	return 0;
}

static __u64 config_read(struct virtio_pci_device *d, unsigned int off,
			 unsigned int width)
{
	__u32 value = 0;

	if (!d->failed && pci_config_read(&d->pdev->addr, off, width, &value))
		d->failed = 1;
	return value;
}

static void config_write(struct virtio_pci_device *d, unsigned int off,
			 unsigned int width, __u32 value)
{
	if (!d->failed &&
	    pci_config_write(&d->pdev->addr, off, width, value))
		d->failed = 1;
}

static __u64 pci_read(struct virtio_pci_device *d, __u64 address, unsigned int width)
{
	__u64 value = 0;

	if (!d->failed)
		virtio_pci_mmio(d, address, &value, width, 0);
	return value;
}

static void pci_write(struct virtio_pci_device *d, __u64 address, unsigned int width,
		      __u64 value)
{
	if (!d->failed)
		virtio_pci_mmio(d, address, &value, width, 1);
}

static __u64 common_read(struct virtio_pci_device *d, unsigned int off,
			unsigned int width)
{
	return pci_read(d, d->common + off, width);
}

static void common_write(struct virtio_pci_device *d, unsigned int off,
			 unsigned int width, __u64 value)
{
	pci_write(d, d->common + off, width, value);
}

static int virtio_pci_msix_disable(struct virtio_pci_device *d)
{
	__u32 config_value;
	__u64 control = 0, mask = VIRTIO_MSIX_VECTOR_MASK;
	int rc;

	d->irq_enabled = 0;
	if (!d->msix_cap)
		return 0;
	/* Cleanup must still attempt source masking after a failed normal access. */
	rc = pci_config_read(&d->pdev->addr, d->msix_cap + 2, 2,
			     &config_value);
	if (!rc)
		control = config_value;
	if (!rc) {
		control &= ~(VIRTIO_MSIX_MASK | VIRTIO_MSIX_ENABLE);
		rc = pci_config_write(&d->pdev->addr, d->msix_cap + 2, 2,
				      control);
	}
	if (virtio_pci_mmio(d, d->msix_table + 12, &mask, 4, 1))
		rc = -EIO;
	if (!rc) {
		rc = pci_config_read(&d->pdev->addr, d->msix_cap + 2, 2,
				     &config_value);
		if (!rc)
			control = config_value;
		if (!rc && (control & VIRTIO_MSIX_ENABLE))
			rc = -EIO;
	}
	if (!rc) {
		rc = virtio_pci_mmio(d, d->msix_table + 12, &mask, 4, 0);
		if (!rc && mask != VIRTIO_MSIX_VECTOR_MASK)
			rc = -EIO;
	}
	if (rc)
		uk_pr_err("VIRTIO_MSIX_DISABLE_FAIL rc=%d control=0x%llx expected_enable=0 table_mask=0x%llx expected_table_mask=1; retaining IRQ-visible state\n",
			  rc, (unsigned long long)control, (unsigned long long)mask);
	else
		uk_pr_info("VIRTIO_MSIX_DISABLED control=0x%llx table_mask=0x%llx global_enable=0\n",
			   (unsigned long long)control, (unsigned long long)mask);
	return rc;
}

static void virtio_irq_count(__u64 *counter)
{
	__u64 value = __atomic_load_n(counter, __ATOMIC_RELAXED);

	/* This fixed platform targets only BSP APIC 0. Counters saturate. */
	if (value != ~(__u64)0)
		__atomic_store_n(counter, value + 1, __ATOMIC_RELAXED);
}

static int virtio_pci_handle_irq(void *arg)
{
	struct virtio_pci_device *d = arg;
	struct virtqueue *q;
	unsigned int i;

	virtio_irq_count(&d->irq_count);
	if (!d->irq_enabled || d->failed)
		return 1;
	for (i = 0; i < VIRTIO_PCI_QUEUES; i++) {
		q = d->queues[i];
		/* TX has no callback; only its sender may reclaim its completions. */
		if (q && q->vq_callback && virtqueue_hasdata(q)) {
			virtio_irq_count(&d->queue_irqs[i]);
			virtqueue_ring_interrupt(q);
		}
	}
	return 1;
}

static int virtio_pci_irq_init(struct virtio_pci_device *d)
{
	int rc = virtio_pci_msix_disable(d);

	if (rc)
		return rc;
	rc = uk_intctlr_irq_alloc(&d->irq, 1);
	if (rc)
		return rc;
	/* IRQ n maps to IDT 32+n; upper vectors belong to platform sources. */
	if (d->irq >= UK_INTCTLR_MAX_IRQ ||
	    d->irq + VIRTIO_IRQ_VECTOR_BASE >= VIRTIO_IRQ_VECTOR_LIMIT) {
		uk_intctlr_irq_free(&d->irq, 1);
		return -ENOSPC;
	}
	rc = uk_intctlr_irq_register(d->irq, virtio_pci_handle_irq, d);
	if (rc) {
		uk_intctlr_irq_free(&d->irq, 1);
		return rc;
	}
	d->irq_registered = 1;
	return 0;
}

static int virtio_pci_msix_prepare(struct virtio_pci_device *d)
{
	__u64 control, address, data, vector;

	pci_write(d, d->msix_table + 12, 4, VIRTIO_MSIX_VECTOR_MASK);
	pci_write(d, d->msix_table, 4, 0xfee00000);
	pci_write(d, d->msix_table + 4, 4, 0);
	pci_write(d, d->msix_table + 8, 4, d->irq + VIRTIO_IRQ_VECTOR_BASE);
	address = pci_read(d, d->msix_table, 4) |
		  (pci_read(d, d->msix_table + 4, 4) << 32);
	data = pci_read(d, d->msix_table + 8, 4);
	if (d->failed || address != 0xfee00000 ||
	    data != d->irq + VIRTIO_IRQ_VECTOR_BASE ||
	    pci_read(d, d->msix_table + 12, 4) != VIRTIO_MSIX_VECTOR_MASK)
		return -EIO;
	control = config_read(d, d->msix_cap + 2, 2);
	/* OpenVMM has no Function Mask bit. Keep global Enable clear until ready. */
	config_write(d, d->msix_cap + 2, 2,
		     control & ~(VIRTIO_MSIX_ENABLE | VIRTIO_MSIX_MASK));
	control = config_read(d, d->msix_cap + 2, 2);
	common_write(d, 16, 2, VIRTIO_MSIX_ENTRY);
	vector = common_read(d, 16, 2);
	if (d->failed || (control & (VIRTIO_MSIX_ENABLE | VIRTIO_MSIX_MASK)) ||
	    vector != VIRTIO_MSIX_ENTRY) {
		uk_pr_err("VIRTIO_MSIX_PREPARE_FAIL control=0x%llx expected_control_bits=0 config_vector=0x%llx expected_vector=0\n",
			  (unsigned long long)control, (unsigned long long)vector);
		return -EIO;
	}
	uk_pr_info("VIRTIO_MSIX_CONFIG irq=%u vector=%u entry=0 count=%u table=0x%llx address=0x%llx data=0x%llx control=0x%llx config_vector=0\n",
		   d->irq, d->irq + VIRTIO_IRQ_VECTOR_BASE, d->msix_count,
		   (unsigned long long)d->msix_table, (unsigned long long)address,
		   (unsigned long long)data, (unsigned long long)control);
	return 0;
}

static void virtio_pci_reset(struct virtio_dev *v)
{
	struct virtio_pci_device *d = to_virtio_pci(v);
	unsigned int i;

	if (virtio_pci_msix_disable(d)) {
		d->failed = 1;
		return;
	}
	common_write(d, 20, 1, 0);
	for (i = 0; i < 100; i++) {
		if (!common_read(d, 20, 1))
			return;
		uk_sched_thread_sleep(1000000);
	}
	d->failed = 1;
}

static __u8 virtio_pci_status_get(struct virtio_dev *v)
{
	struct virtio_pci_device *d = to_virtio_pci(v);
	__u8 status = common_read(d, 20, 1);

	return d->failed ? VIRTIO_CONFIG_STATUS_FAIL : status;
}

static void virtio_pci_status_set(struct virtio_dev *v, __u8 status)
{
	struct virtio_pci_device *d = to_virtio_pci(v);
	__u64 control, mask;

	if (status & VIRTIO_CONFIG_STATUS_FAIL)
		virtio_pci_msix_disable(d);
	common_write(d, 20, 1, status);
	if (!(status & VIRTIO_CONFIG_STATUS_DRIVER_OK) || d->failed)
		return;
	if (!(common_read(d, 20, 1) & VIRTIO_CONFIG_STATUS_DRIVER_OK)) {
		d->failed = 1;
		uk_pr_err("VIRTIO_PCI_DRIVER_OK_READBACK_FAIL\n");
		return;
	}
	d->irq_enabled = 1;
	pci_write(d, d->msix_table + 12, 4, 0);
	control = config_read(d, d->msix_cap + 2, 2);
	config_write(d, d->msix_cap + 2, 2,
		     (control | VIRTIO_MSIX_ENABLE) & ~VIRTIO_MSIX_MASK);
	control = config_read(d, d->msix_cap + 2, 2);
	mask = pci_read(d, d->msix_table + 12, 4);
	if (d->failed || (control & (VIRTIO_MSIX_ENABLE | VIRTIO_MSIX_MASK)) != VIRTIO_MSIX_ENABLE ||
	    mask) {
		virtio_pci_msix_disable(d);
		d->failed = 1;
		uk_pr_err("VIRTIO_MSIX_ENABLE_FAIL control=0x%llx expected_control_bits=0x8000 table_mask=0x%llx expected_table_mask=0\n",
			  (unsigned long long)control, (unsigned long long)mask);
		return;
	}
	uk_pr_info("VIRTIO_MSIX_ENABLED vector=%u control=0x%llx polling=0\n",
		   d->irq + VIRTIO_IRQ_VECTOR_BASE, (unsigned long long)control);
}

static __u64 virtio_pci_features_get(struct virtio_dev *v)
{
	struct virtio_pci_device *d = to_virtio_pci(v);
	__u64 features;

	common_write(d, 0, 4, 0);
	features = common_read(d, 4, 4);
	common_write(d, 0, 4, 1);
	features |= common_read(d, 4, 4) << 32;
	if (!(features & (1ULL << VIRTIO_F_VERSION_1)))
		d->failed = 1;
	return d->failed ? 0 : features;
}

static void virtio_pci_features_set(struct virtio_dev *v)
{
	struct virtio_pci_device *d = to_virtio_pci(v);

	v->features = virtqueue_feature_negotiate(v->features);
	if (!(v->features & (1ULL << VIRTIO_F_VERSION_1))) {
		d->failed = 1;
		return;
	}
	common_write(d, 8, 4, 0);
	common_write(d, 12, 4, (__u32)v->features);
	common_write(d, 8, 4, 1);
	common_write(d, 12, 4, v->features >> 32);
	if (virtio_pci_msix_prepare(d)) {
		virtio_pci_msix_disable(d);
		d->failed = 1;
		uk_pr_err("VIRTIO_MSIX_CONFIG_FAIL\n");
	}
}

static int virtio_pci_config_get(struct virtio_dev *v, __u16 off, void *buf,
			      __u32 len, __u8 width)
{
	struct virtio_pci_device *d = to_virtio_pci(v);
	__u64 value;
	__u8 generation;
	unsigned int attempt, i;

	if (!d->device ||
	    (width != 1 && width != 2 && width != 4 && width != 8) ||
	    len % width || off > d->device_len || len > d->device_len - off)
		return -EINVAL;
	for (attempt = 0; attempt < 16; attempt++) {
		generation = common_read(d, 21, 1);
		for (i = 0; i < len; i += width) {
			value = pci_read(d, d->device + off + i, width);
			memcpy((char *)buf + i, &value, width);
		}
		if (d->failed)
			return -EIO;
		if (generation == common_read(d, 21, 1))
			return d->failed ? -EIO : 0;
	}
	return -EIO;
}

static int virtio_pci_config_set(struct virtio_dev *v, __u16 off,
			      const void *buf, __u32 len)
{
	struct virtio_pci_device *d = to_virtio_pci(v);
	unsigned int i;

	if (!d->device || off > d->device_len || len > d->device_len - off)
		return -EINVAL;
	for (i = 0; i < len; i++)
		pci_write(d, d->device + off + i, 1, ((const __u8 *)buf)[i]);
	return d->failed ? -EIO : 0;
}

static int virtio_pci_find_queues(struct virtio_dev *v, __u16 count, __u16 *sizes)
{
	struct virtio_pci_device *d = to_virtio_pci(v);
	unsigned int i;

	if (count > VIRTIO_PCI_QUEUES || common_read(d, 18, 2) < count)
		return -EINVAL;
	for (i = 0; i < count; i++) {
		common_write(d, 22, 2, i);
		sizes[i] = MIN(common_read(d, 24, 2), (__u64)64);
		if (!sizes[i] || (sizes[i] & (sizes[i] - 1)))
			return -EINVAL;
	}
	return d->failed ? -EIO : count;
}

static int virtio_pci_notify(struct virtio_dev *v, __u16 id)
{
	struct virtio_pci_device *d = to_virtio_pci(v);

	if (id >= VIRTIO_PCI_QUEUES)
		return -EINVAL;
	pci_write(d, d->notify_addr[id], 2, id);
	return d->failed ? -EIO : 0;
}

static struct virtqueue *virtio_pci_setup_queue(struct virtio_dev *v, __u16 id,
					    __u16 size, virtqueue_callback_t cb,
					    struct uk_alloc *a)
{
	struct virtio_pci_device *d = to_virtio_pci(v);
	struct virtqueue *q;
	__u64 offset;
	__u16 vector, readback;

	if (id >= VIRTIO_PCI_QUEUES || d->queues[id])
		return ERR2PTR(-EINVAL);
	common_write(d, 22, 2, id);
	if (size > common_read(d, 24, 2))
		return ERR2PTR(-EINVAL);
	offset = common_read(d, 30, 2) * d->notify_multiplier;
	if (d->notify_len < 2 || offset > d->notify_len - 2)
		return ERR2PTR(-EINVAL);
	q = virtqueue_create(id, size, __PAGE_SIZE, cb, virtio_pci_notify, v, a);
	if (PTRISERR(q))
		return q;
	d->notify_addr[id] = d->notify + offset;
	d->queues[id] = q;
	common_write(d, 24, 2, size);
	vector = cb ? VIRTIO_MSIX_ENTRY : VIRTIO_PCI_NO_VECTOR;
	common_write(d, 26, 2, vector);
	readback = common_read(d, 26, 2);
	if (d->failed || readback != vector) {
		virtio_pci_msix_disable(d);
		d->failed = 1;
		uk_pr_err("VIRTIO_MSIX_QUEUE_FAIL q=%u expected=%u readback=%u\n",
			  id, vector, readback);
		return ERR2PTR(-EIO);
	}
	common_write(d, 32, 8, virtqueue_physaddr(q));
	common_write(d, 40, 8, virtqueue_get_avail_addr(q));
	common_write(d, 48, 8, virtqueue_get_used_addr(q));
	common_write(d, 28, 2, 1);
	if (d->failed)
		return ERR2PTR(-EIO);
	uk_pr_info("VIRTIO_MSIX_QUEUE q=%u vector=%u callback=%u ready_before_driver_ok=1\n",
		   id, readback, cb != NULL);
	return q;
}

static void virtio_pci_release_queue(struct virtio_dev *v, struct virtqueue *q,
				  struct uk_alloc *a)
{
	struct virtio_pci_device *d = to_virtio_pci(v);

	virtio_pci_reset(v);
	if (d->failed)
		return;
	d->queues[q->queue_id] = NULL;
	virtqueue_destroy(__PAGE_SIZE, q, a);
}

static struct virtio_config_ops virtio_pci_ops = {
	.device_reset = virtio_pci_reset,
	.config_get = virtio_pci_config_get,
	.config_set = virtio_pci_config_set,
	.features_get = virtio_pci_features_get,
	.features_set = virtio_pci_features_set,
	.status_get = virtio_pci_status_get,
	.status_set = virtio_pci_status_set,
	.vqs_find = virtio_pci_find_queues,
	.vq_setup = virtio_pci_setup_queue,
	.vq_release = virtio_pci_release_queue,
};

static int virtio_pci_map_bars(struct virtio_pci_device *d)
{
	unsigned int i;
	__sz len;
	int rc;

	if (!d->pdev)
		return -EINVAL;
	for (i = 0; i < 6; i++) {
		if (!d->pdev->bar[i] || !d->pdev->bar_size[i])
			continue;
		len = UK_PAGING_PAGE_ALIGN_UP(d->pdev->bar_size[i]);
		rc = x86_mmio_map_uc_range(d->pdev->bar[i], len, __NULL);
		if (rc)
			return rc;
	}
	return 0;
}

static int virtio_pci_caps(struct virtio_pci_device *d)
{
	__u32 at = config_read(d, 0x34, 1);
	unsigned int steps, type, bar, pba_bar, caplen, capability;
	__u64 offset, pba_offset, len, pba_len, table;
	__u32 control;

	for (steps = 0; at && steps < 48; steps++) {
		if (at < 0x40 || at > 0xfc || (at & 3))
			return -EINVAL;
		capability = config_read(d, at, 1);
		if (capability == VIRTIO_PCI_CAP_MSIX) {
			control = config_read(d, at + 2, 2);
			table = config_read(d, at + 4, 4);
			pba_offset = config_read(d, at + 8, 4);
			bar = table & 7;
			offset = table & ~7U;
			pba_bar = pba_offset & 7;
			pba_offset &= ~7U;
			d->msix_count = (control & 0x7ff) + 1;
			len = (__u64)d->msix_count * 16;
			pba_len = ((__u64)d->msix_count + 63) / 64 * 8;
			if (bar >= 6 || !d->pdev->bar_size[bar] ||
			    offset > d->pdev->bar_size[bar] ||
			    len > d->pdev->bar_size[bar] - offset ||
			    pba_bar >= 6 || !d->pdev->bar_size[pba_bar] ||
			    pba_offset > d->pdev->bar_size[pba_bar] ||
			    pba_len > d->pdev->bar_size[pba_bar] - pba_offset)
				return -EINVAL;
			d->msix_cap = at;
			d->msix_table = d->pdev->bar[bar] + offset;
			goto next;
		}
		if (capability != VIRTIO_PCI_CAP_VENDOR)
			goto next;
		caplen = config_read(d, at + 2, 1);
		if (caplen < 16 || caplen > 256 - at)
			return -EINVAL;
		type = config_read(d, at + 3, 1);
		/* Only the capability types we actually consume describe a real
		 * BAR window. Other types (notably type 5, VIRTIO_PCI_CAP_PCI_CFG)
		 * carry driver-writable scratch values in bar/offset/length that
		 * are meaningless at probe time, so they must not be validated.
		 */
		if (type != 1 && type != 2 && type != 4)
			goto next;
		bar = config_read(d, at + 4, 1);
		offset = config_read(d, at + 8, 4);
		len = config_read(d, at + 12, 4);
		if (bar >= 6 || !d->pdev->bar_size[bar] ||
		    offset > d->pdev->bar_size[bar] ||
		    len > d->pdev->bar_size[bar] - offset)
			return -EINVAL;
		switch (type) {
		case 1:
			if (len < VIRTIO_PCI_COMMON_MIN || d->common)
				return -EINVAL;
			d->common = d->pdev->bar[bar] + offset;
			break;
		case 2:
			if (caplen < 20 || d->notify)
				return -EINVAL;
			d->notify = d->pdev->bar[bar] + offset;
			d->notify_len = len;
			d->notify_multiplier = config_read(d, at + 16, 4);
			break;
		case 4:
			if (len < 8 || d->device)
				return -EINVAL;
			d->device = d->pdev->bar[bar] + offset;
			d->device_len = len;
			break;
		default:
			break;
		}
next:
		at = config_read(d, at + 1, 1);
	}
	if (at || d->failed || !d->common || !d->notify || !d->msix_cap)
		return -EINVAL;
	return 0;
}

static int virtio_pci_add_dev(struct pci_device *pdev)
{
	struct virtio_pci_device *d;
	__u64 control;
	__u32 command;
	int rc;

	d = uk_calloc(virtio_pci_alloc, 1, sizeof(*d));
	if (!d)
		return -ENOMEM;
	d->pdev = pdev;
	rc = virtio_pci_map_bars(d);
	if (!rc)
		rc = virtio_pci_caps(d);
	if (rc)
		goto fail;
	control = config_read(d, d->msix_cap + 2, 2);
	config_write(d, d->msix_cap + 2, 2,
		     control & ~(VIRTIO_MSIX_MASK | VIRTIO_MSIX_ENABLE));
	rc = pci_config_read(&pdev->addr, PCI_COMMAND_OFFSET, 2, &command);
	if (!rc)
		rc = pci_config_write(&pdev->addr, PCI_COMMAND_OFFSET, 2,
				      command | VIRTIO_PCI_CMD_MEMORY |
				      VIRTIO_PCI_CMD_MASTER |
				      VIRTIO_PCI_CMD_INTX_OFF);
	if (rc || d->failed) {
		rc = rc ? rc : -EIO;
		goto fail;
	}
	rc = virtio_pci_irq_init(d);
	if (rc)
		goto fail;
	d->vdev.id.virtio_device_id = pdev->id.device_id - 0x1040;
	d->vdev.cops = &virtio_pci_ops;
	rc = virtio_bus_register_device(&d->vdev);
	if (rc || d->failed) {
		virtio_pci_msix_disable(d);
		uk_pr_err("Modern virtio PCI registration failed: %d; device retained disabled\n", rc);
		return rc ? rc : -EIO;
	}
	uk_pr_info("Modern virtio PCI device %u ready with MSI-X\n",
		   d->vdev.id.virtio_device_id);
	return 0;
fail:
	uk_pr_err("Modern virtio PCI vsock probe failed: %d\n", rc);
	if (d->irq_registered) {
		if (virtio_pci_msix_disable(d) ||
		    uk_intctlr_irq_unregister(d->irq, virtio_pci_handle_irq))
			return rc;
		uk_intctlr_irq_free(&d->irq, 1);
	}
	uk_free(virtio_pci_alloc, d);
	return rc;
}

static int virtio_pci_init(struct uk_alloc *a)
{
	virtio_pci_alloc = a;
	return 0;
}

static const struct pci_device_id virtio_pci_ids[] = {
	{ PCI_DEVICE_ID(VIRTIO_PCI_VENDOR, 0x1040 + VIRTIO_ID_NET) },
	{ PCI_DEVICE_ID(VIRTIO_PCI_VENDOR, 0x1040 + VIRTIO_ID_BLOCK) },
	{ PCI_DEVICE_ID(VIRTIO_PCI_VENDOR, 0x1040 + VIRTIO_ID_CONSOLE) },
	{ PCI_DEVICE_ID(VIRTIO_PCI_VENDOR, 0x1040 + VIRTIO_ID_RNG) },
	{ PCI_DEVICE_ID(VIRTIO_PCI_VENDOR, 0x1040 + VIRTIO_ID_9P) },
	{ PCI_DEVICE_ID(VIRTIO_PCI_VENDOR, 0x1040 + VIRTIO_ID_VSOCK) },
	{ PCI_DEVICE_ID(VIRTIO_PCI_VENDOR, 0x1040 + VIRTIO_ID_FS) },
	{ PCI_ANY_DEVICE_ID },
};

static struct pci_driver virtio_pci_driver = {
	.device_ids = virtio_pci_ids,
	.init = virtio_pci_init,
	.add_dev = virtio_pci_add_dev,
};
PCI_REGISTER_DRIVER(&virtio_pci_driver);
