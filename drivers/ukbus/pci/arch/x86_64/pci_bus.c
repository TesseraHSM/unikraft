/* TODO: SPDX Header */
/*
 * Authors: Simon Kuenzer <simon.kuenzer@neclab.eu>
 *          Hugo Lefeuvre <hugo.lefeuvre@neclab.eu>
 *
 * Copyright (c) 2018, NEC Europe Ltd., NEC Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
/* Some code was derived from Solo5: */
/*
 * Copyright (c) 2015-2017 Contributors as noted in the AUTHORS file
 *
 * This file is part of Solo5, a unikernel base layer.
 *
 * Permission to use, copy, modify, and/or distribute this software
 * for any purpose with or without fee is hereby granted, provided
 * that the above copyright notice and this permission notice appear
 * in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
 * OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
/*
 * x86 PCI configuration backends and enumeration.
 *
 * ACPI MCFG is preferred when firmware publishes it. The legacy CF8/CFC
 * mechanism remains as a fallback for existing PC-compatible guests.
 */
#include <errno.h>
#include <string.h>
#include <uk/alloc.h>
#include <uk/arch/util.h>
#include <uk/bus/pci.h>
#include <uk/essentials.h>
#include <uk/print.h>
#if CONFIG_LIBUKACPI
#include <uk/acpi.h>
#include <x86/mmio.h>
#endif

#define PCI_ECAM_BUS_SIZE	(1ULL << 20)
#define PCI_ECAM_MAX_WINDOWS	8

struct pci_ecam_window {
	__u64 base;
	__u16 segment;
	__u8 start_bus;
	__u8 end_bus;
};

static struct pci_ecam_window ecam_windows[PCI_ECAM_MAX_WINDOWS];
static unsigned int ecam_window_count;
static __u8 visited_buses[PCI_MAX_BUSES];
static struct uk_alloc *pci_alloc;

static int pci_ecam_add_window(unsigned int index, __u64 base, __u16 segment,
			       __u8 start_bus, __u8 end_bus)
{
	__u64 start, buses, len;
	int rc;

	if (index >= PCI_ECAM_MAX_WINDOWS || start_bus > end_bus ||
	    (base & (PCI_ECAM_BUS_SIZE - 1)))
		return -EINVAL;
	start = base + (__u64)start_bus * PCI_ECAM_BUS_SIZE;
	buses = (__u64)end_bus - start_bus + 1;
	len = buses * PCI_ECAM_BUS_SIZE;
	if (start < base || start > ~0ULL - len)
		return -EOVERFLOW;
	rc = x86_mmio_map_uc_range(start, len, __NULL);
	if (rc)
		return rc;
	ecam_windows[index].base = base;
	ecam_windows[index].segment = segment;
	ecam_windows[index].start_bus = start_bus;
	ecam_windows[index].end_bus = end_bus;
	return 0;
}

static struct pci_ecam_window *
pci_ecam_find(const struct pci_address *addr)
{
	unsigned int i;

	for (i = 0; i < ecam_window_count; i++)
		if (ecam_windows[i].segment == addr->domain &&
		    addr->bus >= ecam_windows[i].start_bus &&
		    addr->bus <= ecam_windows[i].end_bus)
			return &ecam_windows[i];
	return __NULL;
}

static __u64 pci_ecam_address(const struct pci_ecam_window *window,
			      const struct pci_address *addr,
			      unsigned int where)
{
	return window->base + ((__u64)addr->bus << 20) +
	       ((__u64)addr->devid << 15) +
	       ((__u64)addr->function << 12) + where;
}

static int pci_config_valid(const struct pci_address *addr, unsigned int where,
			    unsigned int size)
{
	if (!addr || addr->devid >= PCI_MAX_DEVICES ||
	    addr->function >= PCI_MAX_FUNCTIONS)
		return 0;
	if (size != 1 && size != 2 && size != 4)
		return 0;
	return where <= 4096 - size && !(where & (size - 1));
}

int pci_config_read(const struct pci_address *addr, unsigned int where,
		    unsigned int size, __u32 *value)
{
	struct pci_ecam_window *window;
	__u64 mmio;
	__u32 data;
	unsigned int shift;

	if (!value || !pci_config_valid(addr, where, size))
		return -EINVAL;

	window = pci_ecam_find(addr);
	if (window) {
		mmio = pci_ecam_address(window, addr, where);
		if (size == 1)
			*value = *(volatile __u8 *)(__uptr)mmio;
		else if (size == 2)
			*value = *(volatile __u16 *)(__uptr)mmio;
		else
			*value = *(volatile __u32 *)(__uptr)mmio;
		return 0;
	}
	if (ecam_window_count)
		return -ENODEV;

	if (addr->domain || where >= 256)
		return -ENODEV;
	shift = (where & 3) * 8;
	uk_arch_x86_64_outl(PCI_CONFIG_ADDR,
			    PCI_ENABLE_BIT | ((__u32)addr->bus << PCI_BUS_SHIFT) |
			    ((__u32)addr->devid << PCI_DEVICE_SHIFT) |
			    ((__u32)addr->function << PCI_FUNCTION_SHIFT) |
			    (where & ~3U));
	data = uk_arch_x86_64_inl(PCI_CONFIG_DATA);
	if (size == 1)
		data = (data >> shift) & 0xff;
	else if (size == 2)
		data = (data >> shift) & 0xffff;
	*value = data;
	return 0;
}

int pci_config_write(const struct pci_address *addr, unsigned int where,
		     unsigned int size, __u32 value)
{
	struct pci_ecam_window *window;
	__u64 mmio;
	__u32 config, data, mask;
	unsigned int shift;

	if (!pci_config_valid(addr, where, size))
		return -EINVAL;

	window = pci_ecam_find(addr);
	if (window) {
		mmio = pci_ecam_address(window, addr, where);
		if (size == 1)
			*(volatile __u8 *)(__uptr)mmio = (__u8)value;
		else if (size == 2)
			*(volatile __u16 *)(__uptr)mmio = (__u16)value;
		else
			*(volatile __u32 *)(__uptr)mmio = value;
		return 0;
	}
	if (ecam_window_count)
		return -ENODEV;

	if (addr->domain || where >= 256)
		return -ENODEV;
	config = PCI_ENABLE_BIT | ((__u32)addr->bus << PCI_BUS_SHIFT) |
		 ((__u32)addr->devid << PCI_DEVICE_SHIFT) |
		 ((__u32)addr->function << PCI_FUNCTION_SHIFT) |
		 (where & ~3U);
	if (size == 4) {
		uk_arch_x86_64_outl(PCI_CONFIG_ADDR, config);
		uk_arch_x86_64_outl(PCI_CONFIG_DATA, value);
		return 0;
	}

	shift = (where & 3) * 8;
	mask = (size == 1 ? 0xffU : 0xffffU) << shift;
	uk_arch_x86_64_outl(PCI_CONFIG_ADDR, config);
	data = uk_arch_x86_64_inl(PCI_CONFIG_DATA);
	data = (data & ~mask) | ((value << shift) & mask);
	uk_arch_x86_64_outl(PCI_CONFIG_ADDR, config);
	uk_arch_x86_64_outl(PCI_CONFIG_DATA, data);
	return 0;
}

#if CONFIG_LIBUKACPI
static int pci_ecam_init(void)
{
	const struct uk_acpi_sdt_hdr *hdr;
	const struct uk_acpi_mcfg_entry *entry;
	const struct uk_acpi_mcfg *mcfg;
	unsigned int count, i;
	int rc;

	hdr = uk_acpi_get_table(UK_ACPI_MCFG_SIG, 0);
	if (!hdr)
		return -ENOENT;
	if (hdr->tab_len < sizeof(*mcfg) ||
	    (hdr->tab_len - sizeof(*mcfg)) % sizeof(*entry))
		return -EINVAL;

	mcfg = (const struct uk_acpi_mcfg *)hdr;
	count = (hdr->tab_len - sizeof(*mcfg)) / sizeof(*entry);
	if (!count || count > PCI_ECAM_MAX_WINDOWS)
		return -ENOSPC;

	entry = (const struct uk_acpi_mcfg_entry *)mcfg->entries;
	for (i = 0; i < count; i++, entry++) {
		if (entry->reserved)
			return -EINVAL;
		rc = pci_ecam_add_window(i, entry->base, entry->segment,
					 entry->start_bus, entry->end_bus);
		if (rc)
			return rc;
	}
	ecam_window_count = count;
	return 0;
}
#else
static int pci_ecam_init(void)
{
	return -ENOENT;
}
#endif

static void pci_read_bars(struct pci_device *dev)
{
	unsigned int i;
	__u32 command, low, high, mask_low, mask_high;
	__u64 mask;

	if (pci_config_read(&dev->addr, PCI_COMMAND_OFFSET, 2, &command))
		return;
	pci_config_write(&dev->addr, PCI_COMMAND_OFFSET, 2, command & ~3U);
	for (i = 0; i < ARRAY_SIZE(dev->bar); i++) {
		if (pci_config_read(&dev->addr, PCI_BASE_ADDRESS_0 + i * 4,
				    4, &low))
			break;
		if (!low || low == 0xffffffff || (low & 1)) {
			dev->bar[i] = low & ~3U;
			continue;
		}
		dev->bar[i] = low & ~0xfU;
		pci_config_write(&dev->addr, PCI_BASE_ADDRESS_0 + i * 4,
				 4, 0xffffffff);
		pci_config_read(&dev->addr, PCI_BASE_ADDRESS_0 + i * 4,
				4, &mask_low);
		pci_config_write(&dev->addr, PCI_BASE_ADDRESS_0 + i * 4,
				 4, low);
		if ((low & 6) == 4 && i + 1 < ARRAY_SIZE(dev->bar)) {
			if (pci_config_read(&dev->addr,
					    PCI_BASE_ADDRESS_0 + (i + 1) * 4,
					    4, &high))
				break;
			pci_config_write(&dev->addr,
					 PCI_BASE_ADDRESS_0 + (i + 1) * 4,
					 4, 0xffffffff);
			pci_config_read(&dev->addr,
					PCI_BASE_ADDRESS_0 + (i + 1) * 4,
					4, &mask_high);
			pci_config_write(&dev->addr,
					 PCI_BASE_ADDRESS_0 + (i + 1) * 4,
					 4, high);
			dev->bar[i] |= (__u64)high << 32;
			mask = ((__u64)mask_high << 32) |
			       (mask_low & ~0xfU);
			if (mask)
				dev->bar_size[i] = ~mask + 1;
			i++;
		} else {
			mask = mask_low & ~0xfU;
			if (mask)
				dev->bar_size[i] = (__u32)(~(__u32)mask + 1);
		}
	}
	pci_config_write(&dev->addr, PCI_COMMAND_OFFSET, 2, command);
	dev->base = (unsigned long)dev->bar[0];
}

static int pci_driver_add_device(struct pci_driver *drv,
				 const struct pci_address *addr,
				 const struct pci_device_id *devid)
{
	struct pci_device *dev;
	__u32 irq;
	int rc;

	dev = uk_calloc(pci_alloc, 1, sizeof(*dev));
	if (!dev)
		return -ENOMEM;
	memcpy(&dev->id, devid, sizeof(*devid));
	memcpy(&dev->addr, addr, sizeof(*addr));
	dev->drv = drv;
	pci_read_bars(dev);
	if (!pci_config_read(addr, PCI_CONF_IRQ, 1, &irq))
		dev->irq = irq;

	rc = drv->add_dev(dev);
	if (rc < 0) {
		uk_pr_err("PCI %04x:%02x:%02x.%x: driver initialization failed: %d\n",
			  addr->domain, addr->bus, addr->devid, addr->function,
			  rc);
		uk_free(pci_alloc, dev);
		return rc;
	}
	_pci_register_device(dev);
	return 0;
}

static int probe_function(const struct pci_address *addr)
{
	struct pci_device_id id;
	struct pci_driver *drv;
	__u32 value;

	if (pci_config_read(addr, 0, 4, &value) || (value & 0xffff) == 0xffff)
		return -ENODEV;
	memset(&id, 0, sizeof(id));
	id.vendor_id = value & 0xffff;
	id.device_id = value >> 16;
	pci_config_read(addr, 8, 4, &value);
	id.class_id = value >> 24;
	id.sub_class_id = (value >> 16) & 0xff;
	pci_config_read(addr, 0x2c, 4, &value);
	id.subsystem_vendor_id = value & 0xffff;
	id.subsystem_device_id = value >> 16;

	uk_pr_info("PCI %04x:%02x:%02x.%x class=%02x:%02x id=%04x:%04x",
		   addr->domain, addr->bus, addr->devid, addr->function,
		   id.class_id, id.sub_class_id, id.vendor_id, id.device_id);
	drv = pci_find_driver(&id);
	if (!drv) {
		uk_pr_info(" <no driver>\n");
		return 0;
	}
	uk_pr_info(" driver=%p\n", drv);
	return pci_driver_add_device(drv, addr, &id);
}

static void probe_bus(__u16 segment, __u8 bus)
{
	struct pci_address addr = { .domain = segment, .bus = bus };
	__u32 header, buses;
	unsigned int dev, fn, functions;

	if (visited_buses[bus])
		return;
	visited_buses[bus] = 1;
	for (dev = 0; dev < PCI_MAX_DEVICES; dev++) {
		addr.devid = dev;
		addr.function = 0;
		if (pci_config_read(&addr, 0, 4, &header) ||
		    (header & 0xffff) == 0xffff)
			continue;
		pci_config_read(&addr, PCI_HEADER_TYPE, 1, &header);
		functions = (header & PCI_HEADER_MULTI_FUNC) ?
			    PCI_MAX_FUNCTIONS : 1;
		for (fn = 0; fn < functions; fn++) {
			addr.function = fn;
			if (probe_function(&addr))
				continue;
			pci_config_read(&addr, 8, 4, &header);
			if ((header >> 16) != 0x0604)
				continue;
			if (!pci_config_read(&addr, 0x18, 4, &buses) &&
			    ((buses >> 8) & 0xff) != bus)
				probe_bus(segment, (buses >> 8) & 0xff);
		}
	}
}

int arch_pci_probe(struct uk_alloc *pha)
{
	unsigned int i;
	int rc;

	pci_alloc = pha;
	rc = pci_ecam_init();
	if (!rc) {
		for (i = 0; i < ecam_window_count; i++) {
			memset(visited_buses, 0, sizeof(visited_buses));
			probe_bus(ecam_windows[i].segment,
				  ecam_windows[i].start_bus);
		}
		return 0;
	}
	if (rc != -ENOENT)
		return rc;

	probe_bus(0, 0);
	return 0;
}
