/* SPDX-License-Identifier: BSD-3-Clause */
/* Copyright (c) Microsoft Corporation.
 * Licensed under the BSD-3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 */

/*
 * Nested page faults that carry a device access, and what to do with them.
 *
 * The decoder below is deliberately small. It recognises the MOV forms a
 * compiler emits for a volatile load or store through a pointer - which is
 * every access a driver written against a mapped BAR makes - and nothing
 * else. Anything wider than that is refused rather than guessed at: a wrong
 * guess here would write the wrong register or move the wrong number of
 * bytes, and neither failure announces itself.
 *
 * Nothing in this file may take a #VC of its own. The console is port I/O, so
 * it cannot report; a refusal is recorded and the caller stops the guest,
 * which is the same answer an unserviceable exit has always had here.
 */
#include <errno.h>
#include <string.h>
#include <uk/arch/limits.h>
#include <uk/arch/types.h>
#include <uk/essentials.h>
#include <uk/plat/shmem.h>
#include <x86/snp_mmio.h>

#define SNP_MMIO_MAX_REGIONS 8
#define SNP_MMIO_MAX_INSN 15

/* Registers as the instruction encoding numbers them, so that a ModRM field
 * indexes this array directly.
 */
#define SNP_REG_RSP 4

struct snp_mmio_region {
	__vaddr_t va;
	__vaddr_t end;
	__paddr_t gpa;
	struct snp_mmio_stats *stats;
	int active;
};

static struct snp_mmio_region snp_mmio_regions[SNP_MMIO_MAX_REGIONS];
static struct snp_mmio_fault snp_mmio_fault;
static int snp_mmio_busy;

int snp_mmio_region_register(__vaddr_t va, __sz len, __paddr_t gpa,
			     struct snp_mmio_stats *stats)
{
	struct snp_mmio_region *free_slot = __NULL;
	__vaddr_t end;
	int i;

	if (!len || (va & (__PAGE_SIZE - 1)) || (len & (__PAGE_SIZE - 1)) ||
	    (gpa & (__PAGE_SIZE - 1)))
		return -EINVAL;
	if (va > ~(__vaddr_t)0 - len)
		return -EINVAL;
	end = va + len;

	for (i = 0; i < SNP_MMIO_MAX_REGIONS; i++) {
		struct snp_mmio_region *r = &snp_mmio_regions[i];

		if (!r->active) {
			if (!free_slot)
				free_slot = r;
			continue;
		}
		/* Two ranges that overlap would disagree about which device a
		 * byte belongs to, and only one of them can be right.
		 */
		if (va < r->end && r->va < end)
			return -EEXIST;
	}
	if (!free_slot)
		return -ENOSPC;

	free_slot->va = va;
	free_slot->end = end;
	free_slot->gpa = gpa;
	free_slot->stats = stats;
	/* Published last: the handler reads this without a lock. */
	__atomic_store_n(&free_slot->active, 1, __ATOMIC_RELEASE);
	return 0;
}

int snp_mmio_region_unregister(__vaddr_t va)
{
	int i;

	for (i = 0; i < SNP_MMIO_MAX_REGIONS; i++) {
		struct snp_mmio_region *r = &snp_mmio_regions[i];

		if (!r->active || r->va != va)
			continue;
		__atomic_store_n(&r->active, 0, __ATOMIC_RELEASE);
		r->va = 0;
		r->end = 0;
		r->gpa = 0;
		r->stats = __NULL;
		return 0;
	}
	return -ENOENT;
}

int snp_mmio_active(void)
{
	int i, count = 0;

	for (i = 0; i < SNP_MMIO_MAX_REGIONS; i++)
		if (__atomic_load_n(&snp_mmio_regions[i].active,
				    __ATOMIC_ACQUIRE))
			count++;
	return count;
}

const struct snp_mmio_fault *snp_mmio_last_fault(void)
{
	return &snp_mmio_fault;
}

static struct snp_mmio_region *snp_mmio_lookup(__vaddr_t va, unsigned int width,
					       enum snp_mmio_reason *reason)
{
	int i;

	*reason = SNP_MMIO_UNREGISTERED;
	for (i = 0; i < SNP_MMIO_MAX_REGIONS; i++) {
		struct snp_mmio_region *r = &snp_mmio_regions[i];

		if (!__atomic_load_n(&r->active, __ATOMIC_ACQUIRE))
			continue;
		if (va < r->va || va >= r->end)
			continue;
		/* An access that starts inside a mapping and ends outside it
		 * names two devices, or one device and nothing.
		 */
		if (width > r->end - va) {
			*reason = SNP_MMIO_SPAN;
			return __NULL;
		}
		*reason = SNP_MMIO_OK;
		return r;
	}
	return __NULL;
}

static __u64 snp_mmio_read_bytes(const __u8 *p, unsigned int n)
{
	__u64 value = 0;
	unsigned int i;

	for (i = 0; i < n; i++)
		value |= (__u64)p[i] << (8 * i);
	return value;
}

static __s64 snp_mmio_signed(__u64 value, unsigned int bytes)
{
	unsigned int shift = 64 - 8 * bytes;

	return (__s64)(value << shift) >> shift;
}

/* What one instruction asks for, once it has been read. */
struct snp_mmio_insn {
	unsigned int length;
	unsigned int width;		/* bytes moved to or from the device */
	unsigned int dest_width;	/* bytes of the register a load writes */
	int write;
	int sign_extend;
	int reg;			/* register operand, -1 for an immediate */
	__u64 immediate;
	__vaddr_t address;
	enum snp_mmio_reason reason;
};

static void snp_mmio_decode(const __u8 *code, const unsigned long *regs,
			    __u64 rip, struct snp_mmio_insn *insn)
{
	unsigned int at = 0, opsize = 4, modrm, mod, rm, scale = 0;
	int rex = 0, rex_w = 0, rex_r = 0, rex_x = 0, rex_b = 0;
	int base = -1, index = -1, two_byte = 0;
	__u64 address;
	__s64 displacement = 0;
	__u8 opcode;

	memset(insn, 0, sizeof(*insn));
	insn->reg = -1;

	/* Prefixes. A REX byte only counts as one if it is the last thing
	 * before the opcode, so a legacy prefix after it is not this
	 * instruction.
	 */
	for (;;) {
		if (at >= SNP_MMIO_MAX_INSN) {
			insn->reason = SNP_MMIO_PREFIX;
			return;
		}
		opcode = code[at];
		if (rex && !(opcode >= 0x40 && opcode <= 0x4f))
			break;
		if (opcode == 0x66) {
			opsize = 2;
		} else if (opcode == 0x2e || opcode == 0x36 ||
			   opcode == 0x3e || opcode == 0x26) {
			/* In 64-bit mode CS, DS, ES and SS have no base, so
			 * an override to one of them changes nothing.
			 */
		} else if (opcode >= 0x40 && opcode <= 0x4f) {
			rex = 1;
			rex_w = !!(opcode & 8);
			rex_r = !!(opcode & 4);
			rex_x = !!(opcode & 2);
			rex_b = !!(opcode & 1);
		} else {
			break;
		}
		at++;
	}

	/* 0x67 narrows addressing to 32 bits, 0x64 and 0x65 add a segment
	 * base this decoder does not read, and the lock and repeat prefixes
	 * mean something this decoder does not do. All are refused rather
	 * than ignored.
	 */
	if (opcode == 0x67 || opcode == 0x64 || opcode == 0x65 ||
	    opcode == 0xf0 || opcode == 0xf2 || opcode == 0xf3) {
		insn->reason = SNP_MMIO_PREFIX;
		return;
	}

	if (rex_w)
		opsize = 8;

	if (opcode == 0x0f) {
		two_byte = 1;
		at++;
		if (at >= SNP_MMIO_MAX_INSN) {
			insn->reason = SNP_MMIO_OPCODE;
			return;
		}
		opcode = code[at];
	}
	at++;

	if (two_byte) {
		switch (opcode) {
		case 0xb6:	/* MOVZX r, r/m8 */
			insn->width = 1;
			break;
		case 0xb7:	/* MOVZX r, r/m16 */
			insn->width = 2;
			break;
		case 0xbe:	/* MOVSX r, r/m8 */
			insn->width = 1;
			insn->sign_extend = 1;
			break;
		case 0xbf:	/* MOVSX r, r/m16 */
			insn->width = 2;
			insn->sign_extend = 1;
			break;
		default:
			insn->reason = SNP_MMIO_OPCODE;
			return;
		}
		insn->dest_width = opsize;
	} else {
		switch (opcode) {
		case 0x88:	/* MOV r/m8, r8 */
			insn->width = 1;
			insn->write = 1;
			break;
		case 0x89:	/* MOV r/m, r */
			insn->width = opsize;
			insn->write = 1;
			break;
		case 0x8a:	/* MOV r8, r/m8 */
			insn->width = 1;
			insn->dest_width = 1;
			break;
		case 0x8b:	/* MOV r, r/m */
			insn->width = opsize;
			insn->dest_width = opsize;
			break;
		case 0xc6:	/* MOV r/m8, imm8 */
			insn->width = 1;
			insn->write = 1;
			break;
		case 0xc7:	/* MOV r/m, imm */
			insn->width = opsize;
			insn->write = 1;
			break;
		default:
			insn->reason = SNP_MMIO_OPCODE;
			return;
		}
	}

	if (at >= SNP_MMIO_MAX_INSN) {
		insn->reason = SNP_MMIO_OPERAND;
		return;
	}
	modrm = code[at++];
	mod = modrm >> 6;
	rm = modrm & 7;

	/* mod 3 names a register, so the exit did not come from this operand. */
	if (mod == 3) {
		insn->reason = SNP_MMIO_OPERAND;
		return;
	}

	if (opcode == 0xc6 || opcode == 0xc7) {
		/* The reg field is an opcode extension here, and only /0 is a
		 * MOV; the others are the group 11 encodings.
		 */
		if (((modrm >> 3) & 7) != 0 || rex_r) {
			insn->reason = SNP_MMIO_OPCODE;
			return;
		}
	} else {
		insn->reg = ((modrm >> 3) & 7) | (rex_r << 3);
		/* Without a REX byte, byte register 4 to 7 is AH, CH, DH or
		 * BH - the high half of another register, which this decoder
		 * does not address.
		 */
		if (insn->width == 1 && !insn->sign_extend && !two_byte &&
		    !rex && insn->reg >= 4) {
			insn->reason = SNP_MMIO_REGISTER;
			return;
		}
	}

	if (rm == 4) {
		unsigned int sib;

		if (at >= SNP_MMIO_MAX_INSN) {
			insn->reason = SNP_MMIO_OPERAND;
			return;
		}
		sib = code[at++];
		scale = sib >> 6;
		index = ((sib >> 3) & 7) | (rex_x << 3);
		/* Index 4 without REX.X is the encoding that means no index. */
		if (index == 4)
			index = -1;
		base = (sib & 7) | (rex_b << 3);
		if (mod == 0 && (sib & 7) == 5) {
			base = -1;
			if (at + 4 > SNP_MMIO_MAX_INSN) {
				insn->reason = SNP_MMIO_OPERAND;
				return;
			}
			displacement = snp_mmio_signed(
				snp_mmio_read_bytes(&code[at], 4), 4);
			at += 4;
		}
	} else if (mod == 0 && rm == 5) {
		/* RIP-relative: the displacement is added to the address of
		 * the next instruction, so it is resolved after the length is
		 * known.
		 */
		if (at + 4 > SNP_MMIO_MAX_INSN) {
			insn->reason = SNP_MMIO_OPERAND;
			return;
		}
		displacement = snp_mmio_signed(
			snp_mmio_read_bytes(&code[at], 4), 4);
		at += 4;
		base = -2;
		scale = 0;
	} else {
		base = rm | (rex_b << 3);
		scale = 0;
	}

	if (mod == 1) {
		if (at + 1 > SNP_MMIO_MAX_INSN) {
			insn->reason = SNP_MMIO_OPERAND;
			return;
		}
		displacement = snp_mmio_signed(code[at], 1);
		at += 1;
	} else if (mod == 2) {
		if (at + 4 > SNP_MMIO_MAX_INSN) {
			insn->reason = SNP_MMIO_OPERAND;
			return;
		}
		displacement = snp_mmio_signed(
			snp_mmio_read_bytes(&code[at], 4), 4);
		at += 4;
	}

	if (opcode == 0xc6 || opcode == 0xc7) {
		unsigned int bytes = insn->width == 1 ? 1 :
				     (insn->width == 2 ? 2 : 4);

		if (at + bytes > SNP_MMIO_MAX_INSN) {
			insn->reason = SNP_MMIO_OPERAND;
			return;
		}
		/* The 64-bit form still carries a 32-bit immediate, sign
		 * extended into the operand.
		 */
		insn->immediate = (__u64)snp_mmio_signed(
			snp_mmio_read_bytes(&code[at], bytes), bytes);
		at += bytes;
	}

	insn->length = at;

	address = (__u64)displacement;
	if (base == -2) {
		address += rip + at;
	} else if (base >= 0) {
		if (base == SNP_REG_RSP && rm != 4) {
			/* rm 4 is the SIB escape, so a plain rsp base can only
			 * arrive through SIB; reaching here means the decode
			 * disagrees with itself.
			 */
			insn->reason = SNP_MMIO_OPERAND;
			return;
		}
		address += regs[base];
	}
	if (index >= 0)
		address += regs[index] << scale;
	insn->address = (__vaddr_t)address;

	/* A load writes a register, and rsp is not one this will write: an
	 * emulated store to the stack pointer would change the frame the
	 * handler is about to return through.
	 */
	if (!insn->write && insn->reg == SNP_REG_RSP) {
		insn->reason = SNP_MMIO_REGISTER;
		return;
	}
	insn->reason = SNP_MMIO_OK;
}

static __u64 snp_mmio_reg_read(const unsigned long *regs, int reg,
			       unsigned int width)
{
	__u64 value = regs[reg];

	if (width >= 8)
		return value;
	return value & (((__u64)1 << (8 * width)) - 1);
}

static void snp_mmio_reg_write(unsigned long *regs, int reg, __u64 value,
			       unsigned int width)
{
	__u64 mask;

	/* A 32-bit destination clears the upper half, and a narrower one
	 * leaves the rest of the register standing. This is the whole
	 * difference between a byte load and a word load as far as the
	 * register file is concerned, so it is applied here rather than
	 * assumed anywhere else.
	 */
	if (width >= 8) {
		regs[reg] = value;
		return;
	}
	if (width == 4) {
		regs[reg] = (__u32)value;
		return;
	}
	mask = ((__u64)1 << (8 * width)) - 1;
	regs[reg] = (regs[reg] & ~mask) | (value & mask);
}

static void snp_mmio_record(const struct snp_mmio_insn *insn, __u64 rip,
			    const __u8 *code, enum snp_mmio_reason reason)
{
	unsigned int i, readable = 0;

	snp_mmio_fault.count++;
	snp_mmio_fault.rip = rip;
	snp_mmio_fault.address = insn ? (__u64)insn->address : 0;
	snp_mmio_fault.reason = (__u32)reason;
	snp_mmio_fault.width = insn ? insn->width : 0;

	/* Only the instruction's own bytes are known to be there. The
	 * processor fetched those, so the pages behind them are mapped; the
	 * bytes after it are a different matter, and the page they would fall
	 * in need not exist. Taking a page fault from inside this handler to
	 * fill in a diagnostic would replace a recorded refusal with an
	 * unexplained second fault, so the record stops at the page edge.
	 */
	if (code) {
		readable = (unsigned int)(__PAGE_SIZE
					  - (rip & (__PAGE_SIZE - 1)));
		if (readable > sizeof(snp_mmio_fault.insn))
			readable = sizeof(snp_mmio_fault.insn);
	}
	for (i = 0; i < sizeof(snp_mmio_fault.insn); i++)
		snp_mmio_fault.insn[i] = i < readable ? code[i] : 0;
}

int snp_vc_mmio_emulate(unsigned long *regs, unsigned long *rip)
{
	struct snp_mmio_region *region;
	struct snp_mmio_insn insn;
	enum snp_mmio_reason reason;
	const __u8 *code;
	__paddr_t gpa;
	__u64 value = 0;
	int rc;

	/* The handler runs with interrupts off and nothing it calls takes a
	 * #VC, so arriving here twice means the emulation itself faulted.
	 * Serving that would corrupt the access already in flight.
	 */
	if (snp_mmio_busy) {
		snp_mmio_record(__NULL, *rip, __NULL, SNP_MMIO_REENTERED);
		return 0;
	}
	snp_mmio_busy = 1;

	code = (const __u8 *)(__uptr)*rip;
	snp_mmio_decode(code, regs, (__u64)*rip, &insn);
	if (insn.reason != SNP_MMIO_OK) {
		snp_mmio_record(&insn, *rip, code, insn.reason);
		snp_mmio_busy = 0;
		return 0;
	}

	region = snp_mmio_lookup(insn.address, insn.width, &reason);
	if (!region) {
		snp_mmio_record(&insn, *rip, code, reason);
		snp_mmio_busy = 0;
		return 0;
	}
	gpa = region->gpa + (insn.address - region->va);

	if (insn.write) {
		value = insn.reg >= 0
			? snp_mmio_reg_read(regs, insn.reg, insn.width)
			: insn.immediate;
	}

	rc = ukplat_confidential_mmio(gpa, &value, insn.width, insn.write);
	if (rc) {
		if (region->stats)
			region->stats->errors++;
		snp_mmio_record(&insn, *rip, code, SNP_MMIO_TRANSPORT);
		snp_mmio_busy = 0;
		return 0;
	}

	if (insn.write) {
		if (region->stats)
			region->stats->writes++;
	} else {
		if (region->stats)
			region->stats->reads++;
		if (insn.sign_extend)
			value = (__u64)snp_mmio_signed(value, insn.width);
		snp_mmio_reg_write(regs, insn.reg, value,
				   insn.dest_width ? insn.dest_width
						   : insn.width);
	}

	*rip += insn.length;
	snp_mmio_busy = 0;
	return 1;
}
