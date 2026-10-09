/* SPDX-License-Identifier: BSD-3-Clause */
/* Copyright (c) Microsoft Corporation.
 * Licensed under the BSD-3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 */

#ifndef __UK_PLAT_MSHV_H__
#define __UK_PLAT_MSHV_H__

#include <uk/arch/types.h>
#include <uk/config.h>
#include <uk/essentials.h>

/*
 * Microsoft hypervisor interface, as described by the Hypervisor Top-Level
 * Functional Specification (TLFS). The definitions below match the ones Linux
 * carries in include/mshv/hvgdk_mini.h.
 */

/* Hypervisor CPUID leaves */
/** Vendor identity and maximum leaf. EBX/ECX/EDX read "Microsoft Hv" */
#define MSHV_CPUID_VENDOR_AND_MAX_FUNCTIONS	0x40000000
/** Hypervisor interface identity. EAX reads "Hv#1" */
#define MSHV_CPUID_INTERFACE			0x40000001
/** Hypervisor version */
#define MSHV_CPUID_VERSION			0x40000002
/** Hypervisor feature identification */
#define MSHV_CPUID_FEATURES			0x40000003
/** Which enlightenments the hypervisor recommends this partition use */
#define MSHV_CPUID_ENLIGHTENMENTS		0x40000004
/** Identifies the virtualisation stack running above this partition */
#define MSHV_CPUID_STACK_INTERFACE		0x40000081
/** What that virtualisation stack offers this partition */
#define MSHV_CPUID_STACK_PROPERTIES		0x40000082

/** A VTL below the paravisor's may make SNP guest requests of the firmware.
 *
 * The bit gates two separate doors, and both stay shut without it: the
 * paravisor refuses to part with the communication key, and the hypervisor
 * answers the guest request exit with an invalid-opcode fault rather than
 * carrying it to the security processor.
 */
#define MSHV_ENLIGHTENMENT_LOWER_VTL_GUEST_REQUEST	(1U << 27)

/** The synthetic bus is reached through the layer beneath, not the host */
#define MSHV_STACK_CONFIDENTIAL_VMBUS		(1U << 3)

/*
 * A short tag naming the build of this port, printed on the first MSHV
 * line of every boot. A boot log is only evidence about the code that
 * produced it, and a stale console reads exactly like a fresh one; on a
 * platform where each experiment costs a deployment, a log that cannot name
 * its own build has already wasted a cycle here more than once. Bump this on
 * every change that is going to be deployed. A log with no such tag at all
 * predates the tag and is AL or older.
 */
#define MSHV_RUN_TAG				"AR"

/* "Microsoft Hv", little-endian, split over EBX, ECX and EDX */
#define MSHV_CPUID_VENDOR_EBX			0x7263694D	/* "Micr" */
#define MSHV_CPUID_VENDOR_ECX			0x666F736F	/* "osof" */
#define MSHV_CPUID_VENDOR_EDX			0x76482074	/* "t Hv" */

/* "Hv#1", little-endian, in EAX */
#define MSHV_CPUID_INTERFACE_SIGNATURE	0x31237648

/*
 * MSHV_CPUID_FEATURES EAX bits. These say which synthetic MSRs the
 * partition is actually allowed to touch; reading a synthetic MSR that is not
 * advertised raises #GP.
 */
/** HV_X64_MSR_TIME_REF_COUNT is available */
#define HV_MSR_TIME_REF_COUNT_AVAILABLE		(1UL << 1)
/** The synthetic interrupt controller MSRs are available */
#define HV_MSR_SYNIC_AVAILABLE			(1UL << 2)
/** The synthetic timer MSRs are available */
#define HV_MSR_SYNTIMER_AVAILABLE		(1UL << 3)
/** HV_X64_MSR_VP_INDEX is available */
#define HV_MSR_VP_INDEX_AVAILABLE		(1UL << 6)
/** HV_X64_MSR_RESET is available */
#define HV_MSR_RESET_AVAILABLE			(1UL << 7)
/** HV_X64_MSR_REFERENCE_TSC is available */
#define HV_MSR_REFERENCE_TSC_AVAILABLE		(1UL << 9)
/** HV_X64_MSR_TSC_FREQUENCY and _APIC_FREQUENCY are available */
#define HV_ACCESS_FREQUENCY_MSRS		(1UL << 11)

/*
 * MSHV_CPUID_FEATURES EDX bits.
 */
/** The HV_X64_MSR_CRASH_* MSRs are available */
#define HV_FEATURE_GUEST_CRASH_MSR_AVAILABLE	(1UL << 10)

/* Synthetic MSRs */
/** Guest OS identity. Must be non-zero before the hypercall page is used */
#define HV_X64_MSR_GUEST_OS_ID			0x40000000
/** Hypercall page control */
#define HV_X64_MSR_HYPERCALL			0x40000001
/** Index of the virtual processor reading the MSR */
#define HV_X64_MSR_VP_INDEX			0x40000002
/** Writing 1 resets the partition */
#define HV_X64_MSR_RESET			0x40000003
/** Partition reference time, monotonic, in 100 ns units */
#define HV_X64_MSR_TIME_REF_COUNT		0x40000020
/** Reference TSC page control */
#define HV_X64_MSR_REFERENCE_TSC		0x40000021
/** TSC frequency in Hz */
#define HV_X64_MSR_TSC_FREQUENCY		0x40000022
/** Local APIC timer frequency in Hz */
#define HV_X64_MSR_APIC_FREQUENCY		0x40000023

/* Synthetic interrupt controller MSRs. SIMP, SIEFP and the SINTs are
 * per-virtual-processor; the values below are what the reading processor sees.
 */
/** Synthetic interrupt controller control */
#define HV_X64_MSR_SCONTROL			0x40000080
/** Synthetic interrupt controller version */
#define HV_X64_MSR_SVERSION			0x40000081
/** Synthetic interrupt event flags page */
#define HV_X64_MSR_SIEFP			0x40000082
/** Synthetic interrupt message page */
#define HV_X64_MSR_SIMP				0x40000083
/** Writing ends the current message and lets the hypervisor deliver the next */
#define HV_X64_MSR_EOM				0x40000084
/** First of the sixteen synthetic interrupt source MSRs */
#define HV_X64_MSR_SINT0			0x40000090
/** Synthetic interrupt source @p n, 0 <= n < HV_SYNIC_SINT_COUNT */
#define HV_X64_MSR_SINT(n)			(HV_X64_MSR_SINT0 + (n))

/** Number of synthetic interrupt sources per virtual processor */
#define HV_SYNIC_SINT_COUNT			16
/** The synthetic interrupt source VMBus uses for messages and channel events */
/* The identifier the synthetic bus is reached through */
#define VMBUS_CONNID_MESSAGE		4

/* The synthetic interrupt source VMBus messages and channel events arrive
 * on. It is normally SINT 2, chosen by the protocol. When the host redirects
 * a partition's control plane to a higher privilege level, it creates the
 * message port on SINT 7 of that level instead, so the source a guest has to
 * listen on is not known until the route is chosen. Hence a variable.
 */
extern __u8 mshv_vmbus_sint;
#define HV_SYNIC_SINT_VMBUS			mshv_vmbus_sint

/* The source the protocol names, and the one a connect request always claims
 * even when the answer is redirected somewhere else.
 */
#define HV_SYNIC_SINT_VMBUS_DEFAULT		2
/* The source a redirected control plane is delivered on. */
#define HV_SYNIC_SINT_VMBUS_REDIRECT		7

/**
 * Move VMBus message and event delivery to another synthetic interrupt source.
 *
 * Masks the source being left behind before arming the new one, so an
 * interrupt can never be raised on a source nothing is listening to. Safe to
 * call once the controller is up; a no-op if the source is already current.
 *
 * @param sint  synthetic interrupt source to receive VMBus traffic
 */
void mshv_synic_set_vmbus_sint(__u8 sint);

/*
 * The synthetic interrupt event flags page holds one 256-byte block per
 * interrupt source. Bit 0 of a block is set by the host to say that the
 * source has something pending and is cleared by the guest.
 */
#define HV_SYNIC_EVTFLAGS_SIZE			256

/** Set in HV_X64_MSR_SCONTROL to enable the synthetic interrupt controller */
#define HV_SYNIC_SCONTROL_ENABLE		(1ULL << 0)
/** Set in HV_X64_MSR_SIMP / _SIEFP to enable the page */
#define HV_SYNIC_PAGE_ENABLE			(1ULL << 0)
/** Page frame number field of HV_X64_MSR_SIMP / _SIEFP / _HYPERCALL */
#define HV_SYNIC_PAGE_MASK			(~0xfffULL)

/** Interrupt vector field of a SINT */
#define HV_SYNIC_SINT_VECTOR_MASK		0xffULL
/** Set to stop the source from raising interrupts */
#define HV_SYNIC_SINT_MASKED			(1ULL << 16)
/** Set to have the hypervisor issue the local APIC EOI on our behalf */
/* Set on the hypervisor's copy of an interrupt source register when a
 * paravisor is present: the hypervisor then hands the signal to the paravisor
 * instead of raising it in this partition, and the paravisor injects the
 * vector its own copy of the register names. Without it nothing is delivered.
 */
#define HV_SYNIC_SINT_AUTO_EOI			(1ULL << 17)
/** Synthetic interrupt source @p n is serviced by polling, not a vector */
#define HV_SYNIC_SINT_POLLING			(1ULL << 18)
/** Ask the layer beneath an isolated partition to forward this source */
/** Vector the synthetic interrupt source vmbus uses raises.
 *
 * Chosen high on purpose: an isolated partition's synthetic sources are
 * held by the layer beneath, which reserves the low vectors and refuses a
 * source that would raise one of them.
 */
#define MSHV_SYNIC_VECTOR			0xf3

#define HV_SYNIC_SINT_PROXY			(1ULL << 20)

/** Guest crash enlightenment: five free parameters and a notify bit.
 *
 * Writing the parameters and then setting HV_CRASH_CTL_NOTIFY makes the
 * host log them. Unlike the IGVM error page, which is only harvested when
 * the paravisor faults, this works from any VTL.
 */
#define HV_X64_MSR_CRASH_P0			0x40000100
#define HV_X64_MSR_CRASH_CTL			0x40000105
#define HV_CRASH_CTL_NOTIFY			(1ULL << 63)

/** Per-VP page the hypervisor uses to stage VTL switches */
#define HV_X64_MSR_VP_ASSIST_PAGE		0x40000073

/** Call code of HvCallVtlCall, which enters the next higher VTL */
#define HV_CALL_VTL_CALL			0x11

/** Set in HV_X64_MSR_HYPERCALL to enable the hypercall page */
#define HV_HYPERCALL_ENABLE			(1ULL << 0)

/* Hypercall call codes, in bits [15:0] of the hypercall input value. */
/** Post a message to a connection endpoint */
#define HV_HYPERCALL_GET_PARTITION_ID		0x0046
#define HV_HYPERCALL_POST_MESSAGE		0x005c
/** Signal an event on a connection endpoint */
/** Reads virtual processor registers; never carried over the shared block */
#define HV_HYPERCALL_GET_VP_REGISTERS	0x0050

#define HV_HYPERCALL_SIGNAL_EVENT		0x005d

/** Ask for this VTL's SEV-SNP platform communication key.
 *
 * The hypervisor deliberately leaves this one unimplemented: the key must
 * not leave the guest, so only the paravisor can answer it, and it answers
 * for the calling VTL alone. A caller does not choose which key it gets.
 */
#define HV_HYPERCALL_GET_SNP_VMPCK		0x0134

/** Length of the key that call returns */
#define HV_VMPCK_SIZE				32

/* Which key the firmware will verify a request from this guest against.
 *
 * The paravisor occupies the level above, and hands each level below its
 * own the key belonging to that level. A guest running directly beneath
 * it is therefore two levels down from the most privileged, and names
 * that key in every message it sends.
 */
#define MSHV_SNP_GUEST_VMPL			2

/** Names the calling partition in a hypercall input block */
#define HV_PARTITION_ID_SELF			0xffffffffffffffffULL

/** Bits [15:0] of a hypercall result. Zero means the call succeeded. */
#define HV_HYPERCALL_STATUS_MASK		0xffffULL
#define HV_STATUS_SUCCESS			0x0000
#define HV_STATUS_INVALID_HYPERCALL_CODE	0x0002
#define HV_STATUS_INVALID_HYPERCALL_INPUT	0x0003
#define HV_STATUS_INVALID_ALIGNMENT		0x0004
#define HV_STATUS_INSUFFICIENT_BUFFERS		0x0013
/** The caller is not permitted to make this request */
#define HV_STATUS_ACCESS_DENIED			0x0006
/** The request was permitted, but what it asked for does not exist */
#define HV_STATUS_NOT_FOUND			0x0010

/** Message type reported by an empty synthetic message slot */
#define HV_MSGTYPE_NONE				0
/** Message type carrying a VMBus channel message */
#define HV_MSGTYPE_CHANNEL			1

/** Set in mshv_message.flags when the hypervisor has more to deliver */
#define HV_MSGFLAG_PENDING			0x01

/** Payload capacity of a synthetic message, in bytes */
#define HV_MESSAGE_PAYLOAD_SIZE			240

/**
 * A synthetic message slot, as laid out in the SIMP page.
 *
 * There is one slot per synthetic interrupt source, so the slot for source
 * @p n starts at offset n * sizeof(struct mshv_message).
 */
struct mshv_message {
	__u32 type;
	__u8 payload_size;
	__u8 flags;
	__u16 rsvd;
	__u64 port_id;
	__u8 payload[HV_MESSAGE_PAYLOAD_SIZE];
} __packed;

/**
 * Handler invoked from the synthetic interrupt for each message drained.
 *
 * Runs in interrupt context and must be short.
 *
 * @param msg
 *   The message. Only valid for the duration of the call; the slot is released
 *   as soon as the handler returns.
 */
typedef void (*mshv_msg_handler_t)(const struct mshv_message *msg);

/* Called when the synthetic interrupt is raised without a message behind it */
typedef void (*mshv_evt_handler_t)(void);

/* Synthetic timer MSRs. Four timers per virtual processor. */
#define HV_X64_MSR_STIMER0_CONFIG		0x400000B0
#define HV_X64_MSR_STIMER0_COUNT		0x400000B1
#define HV_X64_MSR_STIMER1_CONFIG		0x400000B2
#define HV_X64_MSR_STIMER1_COUNT		0x400000B3
#define HV_X64_MSR_STIMER2_CONFIG		0x400000B4
#define HV_X64_MSR_STIMER2_COUNT		0x400000B5
#define HV_X64_MSR_STIMER3_CONFIG		0x400000B6
#define HV_X64_MSR_STIMER3_COUNT		0x400000B7

/* Set in a timer's configuration to start it */
#define HV_STIMER_ENABLE			(1ULL << 0)

/* Lets a moment be armed by writing it, rather than only while running */
#define HV_STIMER_AUTO_ENABLE			(1ULL << 3)

/* Which interrupt source a timer's message is delivered on */
#define HV_STIMER_SINT_SHIFT			16

/* The message a timer sends when it expires */
#define HV_MSGTYPE_TIMER_EXPIRED		0x80000010

/* Names a processor its own index, which every partition can read back */
#define HV_REGISTER_VP_INDEX			0x00090003

/* Stands for whichever processor is asking */
#define HV_VP_INDEX_SELF			0xfffffffeU

/* Guest crash notification MSRs */
#define HV_X64_MSR_CRASH_P0			0x40000100
#define HV_X64_MSR_CRASH_P1			0x40000101
#define HV_X64_MSR_CRASH_P2			0x40000102
#define HV_X64_MSR_CRASH_P3			0x40000103
#define HV_X64_MSR_CRASH_P4			0x40000104
#define HV_X64_MSR_CRASH_CTL			0x40000105
/** Writing this bit to HV_X64_MSR_CRASH_CTL reports the crash to the host */
#define HV_CRASH_CTL_CRASH_NOTIFY		(1ULL << 63)

/** HV_X64_MSR_TIME_REF_COUNT and the reference TSC page tick every 100 ns */
#define HV_CLOCK_TICK_NSEC			100

/**
 * Probe for the Microsoft hypervisor.
 *
 * Must be called before any other function in this header. Safe to call on
 * any x86 machine, including bare metal and other hypervisors.
 *
 * @return 1 if running on a MSHV partition, 0 otherwise
 */
int mshv_init(void);

/**
 * Report whether we are running on a MSHV partition.
 *
 * @return 1 if mshv_init() detected MSHV, 0 otherwise
 */
int mshv_available(void);

/**
 * The highest Microsoft hypervisor CPUID leaf the partition implements.
 *
 * Leaves beyond it do not read as zero: x86 returns the contents of the
 * highest implemented leaf instead, so an optional leaf must be bounds-checked
 * against this value before it is interpreted.
 *
 * @return the maximum leaf, or 0 if this is not a MSHV partition
 */
__u32 mshv_max_cpuid_leaf(void);

/**
 * Whether this host expects the synthetic bus to be reached through the
 * layer beneath the partition rather than through the host itself.
 *
 * The two arrangements carry the same messages over different transports, so
 * a guest that chooses the wrong one is not refused: it is simply never
 * answered.
 *
 * @return non-zero when the confidential arrangement is offered
 */
__u32 mshv_stack_properties(void);
__u32 mshv_stack_interface(void);
int mshv_confidential_vmbus(void);

/**
 * Test whether the partition is allowed to use a set of synthetic MSRs.
 *
 * @param features
 *   One or more HV_MSR_*_AVAILABLE / HV_ACCESS_* bits
 *
 * @return 1 if all of the requested features are available, 0 otherwise
 */
int mshv_has_features(__u32 features);

/**
 * Read the partition reference time.
 *
 * This counter is monotonic, starts at partition creation, is unaffected by
 * live migration and by TSC scaling, and is the recommended guest time source
 * on MSHV.
 *
 * @return nanoseconds since partition creation, or 0 if unavailable
 */
__u64 mshv_ref_time_nsec(void);

/**
 * Read the virtual TSC frequency the hypervisor reports for this partition.
 *
 * @return TSC frequency in Hz, or 0 if the frequency MSRs are unavailable
 */
__u64 mshv_tsc_freq(void);

/**
 * Read the local APIC timer frequency the hypervisor reports.
 *
 * @return APIC timer input frequency in Hz, or 0 if unavailable
 */
__u64 mshv_apic_freq(void);

/**
 * Prepare the local APIC timer as the platform's one-shot timer source.
 *
 * Generation 2 machines have no i8254, so the local APIC timer is what wakes
 * a halted processor. The timer's input frequency is taken from
 * HV_X64_MSR_APIC_FREQUENCY when the partition is allowed to read it, and
 * otherwise measured against the partition reference counter.
 *
 * The local APIC must already be enabled, which uk_intctlr_probe() arranges
 * before the platform clock is initialised. Either register window works:
 * x2APIC where the processor has it, memory-mapped xAPIC otherwise, which is
 * what a Generation 2 partition normally presents.
 *
 * @param vector
 *   The interrupt vector the timer should raise
 *
 * @return 0 on success, or a negative errno
 */
int mshv_apic_timer_init(__u8 vector);

/**
 * Arm the local APIC timer to fire once after a delay.
 *
 * Delays longer than mshv_apic_timer_max_nsec() are silently truncated to
 * it, so callers must be prepared for a spurious early wakeup, exactly as they
 * already are with the i8254 one-shot.
 *
 * @param nsec
 *   The delay, in nanoseconds
 */
void mshv_apic_timer_arm_nsec(__u64 nsec);

/** Stop the local APIC timer, so that no further interrupt is raised. */
void mshv_apic_timer_disarm(void);

/**
 * The longest delay the local APIC timer can be armed for in one go.
 *
 * @return the delay in nanoseconds, or 0 if the timer is not initialised
 */
__u64 mshv_apic_timer_max_nsec(void);

#if CONFIG_HAVE_MSHV_SYNIC
/**
 * Determine how, if at all, this partition is hardware-isolated.
 *
 * Reads the hypervisor's isolation configuration and, for an isolated
 * partition, the shared guest physical address boundary (vTOM) that
 * mshv_alloc_shared() aliases through. Safe and cheap to call repeatedly;
 * only the first call probes.
 *
 * The architectural AMD SEV CPUID leaf reports nothing on these partitions,
 * so this is the only reliable way to detect isolation.
 *
 * @return 0 if the partition is usable, whether isolated or not, or a negative
 *         errno if it is isolated in a way this port cannot support
 */
int mshv_isolation_init(void);

/**
 * Report whether guest memory is hardware-isolated from the host.
 *
 * @return non-zero if buffers must be shared explicitly, 0 otherwise
 */
int mshv_isolated(void);

/**
 * Report whether hypercalls must be issued as a bare VMMCALL rather than
 * through the hypervisor-supplied hypercall page.
 *
 * The hypercall page is an overlay: the hypervisor substitutes its own page
 * for the guest frame named in HV_X64_MSR_HYPERCALL and writes the trampoline
 * into it. On an encrypted partition that only works if something inside the
 * encryption domain performs the write, which is what a paravisor does. With
 * no paravisor the frame stays guest-private, the overlay never appears, and
 * calling into the page executes whatever the page happened to contain. The
 * calling convention is the same either way, so the guest simply issues the
 * VMMCALL itself and lets the #VC handler forward it.
 *
 * @return non-zero if hypercalls are issued directly, 0 if through the page
 */
int mshv_hypercall_direct(void);

/* The isolation technology covering a partition, as reported by the
 * hypervisor's isolation configuration leaf.
 */
#define MSHV_ISOLATION_NONE	0
#define MSHV_ISOLATION_VBS	1
#define MSHV_ISOLATION_SNP	2
#define MSHV_ISOLATION_TDX	3

/**
 * Report which isolation technology covers this partition.
 *
 * Unlike mshv_isolated(), which answers the operational question of whether
 * buffers have to be shared explicitly, this names the technology itself.
 *
 * @return one of the MSHV_ISOLATION_* values
 */
__u32 mshv_isolation_type(void);

/**
 * The shared guest physical address boundary (vTOM).
 *
 * A guest physical address below it names private memory; the same address
 * with this bit set names the same DRAM shared with the host in the clear.
 *
 * @return the boundary, or 0 if the partition is not isolated
 */
__u64 mshv_shared_gpa_boundary(void);

/**
 * Report whether a paravisor is present.
 *
 * A paravisor is a privileged component running inside the partition, at a
 * higher VMPL than the guest, that emulates part of the platform on the
 * guest's behalf. It sits inside the guest's encryption domain, so it can
 * read private memory, and it intervenes in operations the guest would
 * otherwise have to take up with the hypervisor directly.
 *
 * @return non-zero if the partition has a paravisor
 */
int mshv_paravisor(void);

/**
 * Map a window onto guest physical memory that is already host-visible.
 *
 * This is for pages the guest does not own and did not publish, including
 * device MMIO. No visibility hypercall, PVALIDATE or page-state change is
 * performed: the pages must already be shared.
 *
 * With vTOM, the shared GPA boundary bit is added to each physical address.
 * In initialized direct C-bit SNP mode, the original GPA is mapped with
 * UK_PAGING_PAGE_ATTR_SHARED so the PTE encryption bit is clear. Other modes
 * are unsupported.
 *
 * Release the mapping with mshv_unmap_gpa(), which keeps the foreign frames.
 * If mapping fails and rollback cannot unmap the partial window, its entire
 * VA reservation is retained rather than risking reuse of live mappings.
 *
 * @param gpa
 *   Guest physical address of the first page, without the shared GPA
 *   boundary bit, and page aligned
 * @param pages
 *   Number of pages to map
 * @param attr
 *   Page attributes, as for uk_paging_page_map()
 *
 * @return a pointer to the mapping, or NULL on failure
 */
void *mshv_map_shared_gpa(__paddr_t gpa, unsigned long pages,
			    unsigned long attr);

/** As above, but for a page inside the guest's own encryption domain */
void *mshv_map_private_gpa(__paddr_t gpa, unsigned long pages,
			     unsigned long attr);

/**
 * Withdraw a mapping made by either of the two above.
 *
 * The frames belong to a device or to whoever placed the page, so only the
 * aliases and the window's own address space are released.
 *
 * @param ptr
 *   The pointer that was returned
 * @param pages
 *   How many pages were mapped
 *
 * @return 0 on success, or a negative errno
 */
int mshv_unmap_gpa(void *ptr, unsigned long pages);

/**
 * Guest physical address to hand to the hypervisor or the host for a buffer.
 *
 * On an isolated partition a shared buffer is reached through an alias that
 * carries the shared GPA boundary bit, so walking the page table for one
 * yields an address with that bit set. That bit is a guest side artefact: it
 * selects the unencrypted view of the page for our own loads and stores. The
 * page itself is named by the address without it, and that is the only form
 * the hypervisor accepts - pointing SIMP at an address with the bit set
 * faults the write rather than returning an error.
 *
 * Use this, not uk_paging_virt_to_phys(), for every address that leaves the
 * guest. It is a no-op on a partition that is not isolated.
 */
__paddr_t mshv_gpa(const void *addr);

/**
 * Allocate a page-aligned buffer the hypervisor is able to read and write.
 *
 * On an isolated partition the buffer is reached through an alias above the
 * shared GPA boundary, so it must be accessed only through the returned
 * pointer; the host sees nothing written any other way. On an ordinary
 * partition this is a plain zeroed aligned allocation.
 *
 * In both cases mshv_gpa() on the returned pointer yields the guest
 * physical address to give the hypervisor, so callers need no
 * isolation-specific code. uk_paging_virt_to_phys() is not a substitute: on
 * an isolated partition it returns the alias, boundary bit included.
 *
 * @param size
 *   Size in bytes. Rounded up to a whole number of pages.
 * @param attr
 *   Page attributes for the mapping, as UK_PAGING_PAGE_ATTR_PROT_*. Use
 *   UK_PAGING_PAGE_ATTR_PROT_RW unless the guest executes from the buffer.
 *
 * @return a pointer to the zeroed buffer, or NULL on failure
 */
void *mshv_alloc_shared(__sz size, unsigned long attr);

/**
 * Publish or withdraw a range named by virtual address.
 *
 * Resolves every page through the page table, so a heap allocation whose
 * frames are scattered is published correctly. Prefer this whenever the range
 * came from an allocator rather than from a known contiguous reservation.
 *
 * @param va
 *   Page-aligned start of the virtual range
 * @param pages
 *   How many pages
 * @param visible
 *   Non-zero to grant the host read/write access, zero to revoke it
 *
 * @return 0 on success, or a negative errno
 */
int mshv_set_range_visibility(__vaddr_t va, unsigned long pages,
				int visible);

/**
 * Release a buffer from mshv_alloc_shared().
 *
 * @param ptr
 *   The pointer that was returned, or NULL
 */
void mshv_free_shared(void *ptr);

/**
 * Bring the hypercall page and the synthetic interrupt controller online.
 *
 * Writes the guest OS identity, establishes the hypercall page, maps this
 * processor's message and event-flag pages, routes the VMBus synthetic
 * interrupt source to an allocated IRQ and enables the controller.
 *
 * Must be called after the page table, the allocator and the interrupt
 * controller are up, and with interrupts enabled or disabled indifferently.
 * Calling it more than once is a no-op that reports the first result.
 *
 * @return 0 on success, or a negative errno
 */
int mshv_synic_init(void);

/**
 * Install the handler invoked for each synthetic message delivered to the
 * VMBus synthetic interrupt source.
 *
 * @param handler
 *   The handler, or NULL to remove the current one
 */
void mshv_synic_set_msg_handler(mshv_msg_handler_t handler);

/**
 * Install the handler invoked when the synthetic interrupt source is raised
 * for a reason other than a message.
 *
 * A channel whose ring has become readable is announced by the host setting a
 * bit in a shared page and raising the same interrupt that carries messages;
 * the interrupt itself says nothing about which channel it was. Whoever owns
 * that page has to look.
 *
 * @param handler
 *   The handler, called in interrupt context, or NULL to remove the current
 *   one
 */
void mshv_synic_set_evt_handler(mshv_evt_handler_t handler);

/**
 * Drain any pending synthetic messages on this processor.
 *
 * The synthetic interrupt is the normal way messages are noticed, but a
 * caller already spinning for a reply can look for itself, which keeps the
 * wait honest on a partition where the interrupt does not arrive.
 */
void mshv_synic_poll(void);

/**
 * @return how many synthetic interrupts have been taken on this processor
 */
unsigned long mshv_synic_intr_count(void);

/* How many messages the drain has handed to the registered handler. */
unsigned long mshv_synic_drained(void);

/**
 * @return the first eight bytes of the message slot VMBus uses, which carry
 *         the message type and flags. Zero means nothing has been delivered.
 */
__u64 mshv_synic_slot_header(void);
void mshv_synic_dump_vmbus_slot(const char *when);

/**
 * Log the header of every message slot that is not empty.
 */
void mshv_synic_dump_slots(void);

/**
 * Choose how posted messages leave the guest.
 *
 * @param on
 *   Non-zero to use the hypercall page directly, zero to use the guest
 *   communication block. Only meaningful on an isolated partition; elsewhere
 *   the hypercall page is the only route and this has no effect.
 */
void mshv_post_message_plain(int on);

/**
 * Returns this processor's VMBus channel event flags, or NULL when the
 * synthetic interrupt controller is not set up. The block is
 * HV_SYNIC_EVTFLAGS_SIZE bytes long and one bit wide per channel.
 */
volatile unsigned long *mshv_synic_evtflags(void);

/**
 * Post a message to a connection endpoint (HvPostMessage).
 *
 * Retries while the hypervisor reports that it has no buffer available.
 *
 * @param connid
 *   The connection identifier to post to
 * @param msgtype
 *   The message type, normally HV_MSGTYPE_CHANNEL
 * @param data
 *   The payload
 * @param dsize
 *   The payload size, at most HV_MESSAGE_PAYLOAD_SIZE
 *
 * @return 0 on success, or a negative errno
 */
int mshv_post_message(__u32 connid, __u32 msgtype, const void *data,
			__sz dsize);

/**
 * A prepared HvSignalEvent input block.
 *
 * The hypercall reads its argument from guest memory by physical address, so
 * the block and its translation are set up once and then reused. Signalling
 * sits on the transmit path of every synthetic device, which is why it may
 * not allocate.
 *
 * The first eight bytes are the input block the hypervisor reads. They are
 * eight-byte aligned, which is both what the hypercall requires and what
 * keeps them from straddling a page boundary.
 */
struct mshv_sigevt {
	__u32 connid;
	__u16 evtflag;
	__u16 rsvd;

	__paddr_t pa;
} __align8;

/**
 * Prepare an event signal for repeated use.
 *
 * @param se
 *   The block to prepare; it must stay live and must not be moved afterwards,
 *   because the hypervisor is given its physical address
 * @param connid
 *   The connection identifier to signal. For a VMBus channel this is the
 *   channel's own connection identifier from its offer, not the bus one.
 * @param evtflag
 *   The event flag number within the connection's flag page
 *
 * @return 0 on success, or a negative errno
 */
int mshv_sigevt_init(struct mshv_sigevt *se, __u32 connid, __u16 evtflag);

/**
 * Signal a prepared event (HvSignalEvent).
 *
 * @param se
 *   A block previously prepared by mshv_sigevt_init()
 *
 * @return 0 on success, or a negative errno
 */
int mshv_sigevt_signal(const struct mshv_sigevt *se);

/**
 * The hypervisor's index for the processor this is called on.
 *
 * Channel messages that name a target processor use this number rather than
 * any platform CPU identifier.
 *
 * @return the virtual processor index, or 0 if the partition may not read it
 */
__u32 mshv_vp_index(void);
#endif /* CONFIG_HAVE_MSHV_SYNIC */

/**
 * Establish the Guest-Hypervisor Communication Block.
 *
 * On an isolated partition the synthetic interrupt controller's registers are
 * emulated, and an emulated register cannot be reached with rdmsr or wrmsr:
 * the instruction does not fault into anything that can service it, and the
 * partition is destroyed. The GHCB is how such an access is handed to the
 * hypervisor instead.
 *
 * Succeeds without doing anything on a partition that is not isolated or has
 * no paravisor, in which case mshv_ghcb_ready() reports that there is no
 * GHCB and callers use the instructions directly.
 *
 * @return 0 on success or a negative errno
 */
int mshv_ghcb_init(void);

int mshv_ghcb_mmio(__paddr_t address, void *value, unsigned int width,
		     int write);

/**
 * Report whether the paravisor's extended GHCB protocol is available.
 *
 * A partition with no paravisor still has a GHCB - the #VC handler cannot
 * work without one - but nothing behind it answers requests for emulated
 * registers or block-borne hypercalls, so this reports zero there and callers
 * use the instructions directly.
 *
 * @return non-zero if mshv_ghcb_rdmsr() and mshv_ghcb_wrmsr() will work
 */
int mshv_ghcb_ready(void);

/**
 * Read an emulated model-specific register through the GHCB.
 *
 * @param msr
 *   Register number
 * @param val
 *   Receives the value read
 *
 * @return 0 on success or a negative errno
 */
int mshv_ghcb_rdmsr(__u32 msr, __u64 *val);

/**
 * Write an emulated model-specific register through the GHCB.
 *
 * @param msr
 *   Register number
 * @param val
 *   Value to write
 *
 * @return 0 on success or a negative errno
 */
int mshv_ghcb_wrmsr(__u32 msr, __u64 val);

/**
 * Make a hypercall through the GHCB.
 *
 * The trampoline reads its input block out of guest memory, which the
 * hypervisor cannot do on an isolated partition for the calls it services
 * itself rather than leaving to the paravisor. Those calls carry their input
 * inside the GHCB instead.
 *
 * @param control
 *   Hypercall control word
 * @param input
 *   Input block, copied into the GHCB
 * @param input_size
 *   Size of the input block in bytes
 *
 * @return the hypercall status
 */
__u64 mshv_ghcb_hypercall(__u64 control, const void *input,
			    __sz input_size);

/**
 * As mshv_ghcb_hypercall(), but naming a page for the hypervisor to
 * write its output to. Pass 0 when the call produces none.
 */
__u64 mshv_ghcb_hypercall_out(__u64 control, const void *input,
				__sz input_size, __paddr_t output_gpa);

/**
 * A value no hypercall status can take, reported when the exit itself was
 * refused and so no status was produced at all.
 */
#define MSHV_VMMCALL_NOT_TAKEN	0xffffffffffffffffULL

/**
 * Make the same request without writing it into the shared block: the
 * request is named in registers and its operands left in memory the
 * hypervisor is permitted to read, for a hypervisor that will not take a
 * request out of the block.
 *
 * @param control
 *   Hypercall control word
 * @param input_gpa
 *   Address of the input block, which must be memory the hypervisor may read
 * @param output_gpa
 *   Address to receive the output, or 0 when the call produces none
 *
 * @return the hypercall status, or MSHV_VMMCALL_NOT_TAKEN
 */
__u64 mshv_ghcb_vmmcall(__u64 control, __u64 input_gpa, __u64 output_gpa);

/**
 * Clear the block down to its published fields before each request.
 *
 * The block is shared with the memory access path, which leaves an exit
 * code and a set of valid-field bits behind it. Those fields overlap the
 * area a hypercall puts its arguments in, so a reader that consults them
 * first sees a stale memory access instead of the call being made.
 */
void mshv_ghcb_hypercall_scrub(int on);
void mshv_ghcb_hypercall_clean(int on);
__u64 mshv_ghcb_msr_value(void);

/** Frame enlightened requests with @p version, @p scrub and @p full_control */
void mshv_ghcb_hypercall_style(int version, int scrub, int full_control);

/** Protocol version this guest and the host agreed on */
__u16 mshv_ghcb_negotiated_version(void);

/** Protocol version found on the GHCB before this guest wrote to it */
__u16 mshv_ghcb_established_version(void);

/** Layout found on the GHCB before this guest wrote to it */
__u32 mshv_ghcb_established_format(void);

/**
 * Record whether output pages are named above the shared GPA boundary.
 */
void mshv_ghcb_output_shared(int on);
int mshv_ghcb_output_is_shared(void);

/**
 * Carry a prepared request to the security processor.
 *
 * Neither page is interpreted here: framing and authentication belong to
 * the caller, which is the only party holding the key. Both must be
 * private to this guest.
 *
 * @param req_gpa
 *   Address of the page holding the authenticated request
 * @param resp_gpa
 *   Address of the page the answer is to be written to
 * @param fw_err
 *   If non-NULL, receives the firmware's own error code, and only that:
 *   a refusal by the layer carrying the request is reported through the
 *   return value instead, because the two numbering spaces are unrelated.
 *   Zero unless -EPROTO is returned.
 *
 * @return 0 if the firmware answered without complaint, -EPROTO if it
 *   refused the message, -EIO if the layer beneath refused to carry it,
 *   -EBUSY if that layer stayed busy across every attempt
 */
/**
 * Install the page the hypervisor writes pending events into.
 *
 * Only meaningful under restricted injection, where the hypervisor may no
 * longer inject a vector directly and raises #HV instead. Registering the
 * page is what makes that exception carry information.
 *
 * @param gpa
 *   Guest physical address of a shared, page-aligned, zeroed page.
 * @return
 *   0 on success, a negative errno otherwise.
 */
int mshv_ghcb_set_doorbell(__paddr_t gpa);

#if CONFIG_MSHV_SNP_RESTRICTED_INJECTION
/**
 * Query direct-mode hypervisor features using GHCB MSR protocol version 2.
 * The non-NULL output is written only on success; the mailbox and caller's
 * interrupt state are restored on every exit.
 */
int mshv_ghcb_hv_features(__u64 *features);
#endif

/**
 * Set up #HV delivery, if the guest was launched with restricted injection.
 *
 * Allocates the doorbell page, registers it, and arms the vector-28 handler.
 * A guest launched with normal injection needs none of this and the call
 * succeeds without doing anything.
 *
 * @return
 *   0 on success, a negative errno otherwise.
 */
int mshv_hv_doorbell_init(void);

/**
 * Whether #HV delivery is active.
 */
__isr int mshv_hv_doorbell_ready(void);

#if CONFIG_MSHV_SNP_RESTRICTED_INJECTION
extern volatile __u16 *mshv_hv_pending_word;
__isr void mshv_hv_doorbell_note(void);
__isr unsigned int mshv_hv_spurious_vector(void);
#endif

/**
 * Acknowledge a #HV so that the next event will ring the doorbell again.
 *
 * Called once on entry to the handler, before any event is read.
 */
void mshv_hv_doorbell_rearm(void);

/**
 * Atomically acknowledge and return the complete GHCB PendingEvent word.
 * The vector and nonmaskable event flags are retained; NoFurtherSignal is
 * cleared by the same exchange. This does not complete interrupt service.
 */
__isr __u16 mshv_hv_doorbell_take(void);

/**
 * Take the next pending event off the doorbell page.
 *
 * @return
 *   The interrupt vector to dispatch, or 0 when the page is drained.
 */
unsigned int mshv_hv_doorbell_next(void);

/**
 * Whether the hypervisor has already retired the interrupt it delivered.
 *
 * Call at handler completion. Any nonzero previous assist byte means no
 * explicit EOI is required; the byte is atomically cleared.
 */
__isr int mshv_hv_no_eoi_required(void);

int mshv_ghcb_guest_request(__paddr_t req_gpa, __paddr_t resp_gpa,
			      __u64 *fw_err);

/**
 * Issue a hypercall through the hypercall page.
 *
 * This is the route the paravisor can see. On an isolated partition the
 * paravisor intercepts a fixed set of call codes on their way from this
 * level to the hypervisor and answers them itself. A request made through
 * the shared block instead is carried straight to the hypervisor, which for
 * a call code only the paravisor implements answers
 * HV_STATUS_INVALID_HYPERCALL_CODE - so anything addressed to the paravisor
 * has to go this way.
 *
 * @param control
 *   Call code, with any repetition count and flags already folded in
 * @param in_pa
 *   Address of the input block, or 0 for a call that takes no input
 * @param out_pa
 *   Address of the page the answer is written to, or 0 for none. The
 *   paravisor can reach this level's private memory, so an answer that must
 *   not be seen by the host is written to a private page, not a shared one.
 *
 * @return the raw status word
 */
__u64 mshv_hypercall(__u64 control, __paddr_t in_pa, __paddr_t out_pa);

/**
 * Report what this partition may learn about itself from the security
 * processor, and how.
 *
 * On an isolated partition with a paravisor the guest holds none of the
 * material the firmware protocol needs: there is no secrets page in the
 * firmware tables, so no communication key and no sequence number. The
 * paravisor keeps both and will hand the key to the VTL beneath it on
 * request - but only where the hypervisor has agreed to carry guest
 * requests from a lower VTL at all. That agreement is announced in CPUID
 * and enforced twice, once at each door, so this reports the announcement
 * and the outcome of actually knocking.
 *
 * Prints its findings; never prints key material.
 *
 * @return 0 if this partition can make SNP guest requests, a negative
 *   errno otherwise.
 */
int mshv_snp_attest_probe(void);

#endif /* __UK_PLAT_MSHV_H__ */
