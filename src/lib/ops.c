#include "ops.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <inttypes.h>
#include <stdalign.h>

#include "stk.h"
#include "buf.h"
#include "util.h"

#ifndef __GNUC__
#define __attribute__(x)
#endif

#define OPFUNC(func) \
	static void func ( \
		struct bsp_ec *ec __attribute__((unused)), \
		struct bsp_vm *vm __attribute__((unused)), \
		const uint32_t src[] __attribute__((unused)), \
		uint32_t *dst[] __attribute__((unused)) \
	)

static void validate_utf8(struct bsp_ec *ec, const char *data, size_t len) {
	const uint8_t *fin = (const uint8_t *)data + len;
	const uint8_t *p = (const uint8_t *)data;

	while (p < fin) {
		uint_fast8_t b = *p++, rem = 0;
		uint32_t cpoint, min;

		/*  */ if ((b & 0x80) == 0x00) {
			continue;
		} else if ((b & 0xe0) == 0xc0) {
			cpoint = b & 0x1f;
			min = 0x80;
			rem = 1;
		} else if ((b & 0xf0) == 0xe0) {
			cpoint = b & 0x0f;
			min = 0x800;
			rem = 2;
		} else if ((b & 0xf8) == 0xf0) {
			cpoint = b & 0x07;
			min = 0x10000;
			rem = 3;
		} else {
			bsp_die(ec, "invalid UTF-8 code unit 0x%02x", *(p - 1));
		}

		while (rem--) {
			if (p >= fin)
				bsp_die(ec, "broken UTF-8 string");
			if ((*p & 0xc0) != 0x80)
				bsp_die(ec, "invalid UTF-8 code unit 0x%02x", *p);
			cpoint <<= 6;
			cpoint |= *p++ & 0x3f;
		}

		if (cpoint < min)
			bsp_die(ec, "overlong UTF-8 sequence for scalar value U+%04X", cpoint);
		if (0xd800 <= cpoint && cpoint <= 0xdfff)
			bsp_die(ec, "invalid (surrogate) Unicode scalar value U+%04X", cpoint);
		if (cpoint > 0x10ffff)
			bsp_die(ec, "invalid Unicode scalar value U+%04X", cpoint);
	}
}

static void bsp_msg_print(struct bsp_ec *ec, struct bsp_vm *vm, const char *msg, size_t length) {
	if (vm->cb == NULL || vm->cb->print == NULL)
		return;
	vm->cb->print(ec, vm, msg, length);
}

/* bufstring address */
OPFUNC(op_bufstring) {
	size_t len;
	const char *data = (const char *)bsp_ps_getsz(ec, vm->ps, src[0], &len);

	validate_utf8(ec, data, len);
	bsp_buf_push(ec, vm, data, len);
}

/* bufnumber any */
OPFUNC(op_bufnumber) {
	char numbuf[sizeof("4294967295")];
	char *bufp = numbuf + sizeof(numbuf);

	uint32_t value = src[0];

	do {
		*--bufp = '0' + (value % 10);
		value /= 10;
	} while (value);

	bsp_buf_push(ec, vm, bufp, numbuf + sizeof(numbuf) - bufp);
}

/* bufchar any */
OPFUNC(op_bufchar) {
	char u8buf[sizeof("\xf4\x8f\xbf\xbf")];
	char *u8p = u8buf;

	/*  */ if (src[0] < 0x80) {
		*u8p++ =          src[0]               ;
	} else if (src[0] < 0x800) {
		*u8p++ = 0xc0 | ( src[0] >>  6)        ;
		*u8p++ = 0x80 | ( src[0]        & 0x3f);
	} else if (src[0] < 0x10000) {
		if (src[0] >= 0xd800 && src[0] <= 0xdfff)
			bsp_die(ec, "invalid (surrogate) Unicode scalar value U+%04X", src[0]);
		*u8p++ = 0xe0 | ( src[0] >> 12)        ;
		*u8p++ = 0x80 | ((src[0] >>  6) & 0x3f);
		*u8p++ = 0x80 | ( src[0]        & 0x3f);
	} else if (src[0] < 0x110000) {
		*u8p++ = 0xf0 | ( src[0] >> 18)        ;
		*u8p++ = 0x80 | ((src[0] >> 12) & 0x3f);
		*u8p++ = 0x80 | ((src[0] >>  6) & 0x3f);
		*u8p++ = 0x80 | ( src[0]        & 0x3f);
	} else {
		bsp_die(ec, "invalid Unicode scalar value U+%04X", src[0]);
	}

	bsp_buf_push(ec, vm, u8buf, u8p - u8buf);
}

/* printbuf */
OPFUNC(op_printbuf) {
	bsp_msg_print(ec, vm, vm->_buf, vm->_buf_used);
	bsp_buf_clear(ec, vm);
}

/* clearbuf */
OPFUNC(op_clearbuf) {
	bsp_buf_clear(ec, vm);
}

/* print addr */
OPFUNC(op_print) {
	size_t len;
	const char *data = bsp_ps_getsz(ec, vm->ps, src[0], &len);

	validate_utf8(ec, data, len);
	bsp_msg_print(ec, vm, data, len);
}

/* nop */
OPFUNC(op_nop) {
	/* nothing */
}

/* exit any */
OPFUNC(op_exit) {
	vm->exit_code = src[0];
	bsp_return(ec, BSP_RET_EXIT);
}

/* jumptable #reg */
OPFUNC(op_jumptable) {
	uint32_t offs = src[0];
	if (offs & 0xc0000000)
		bsp_die(ec, "jump table index overflow");
	offs <<= 2;
	if (vm->pc_next + offs < offs)
		bsp_die(ec, "jump table index overflow");
	offs += vm->pc_next;
	vm->pc_next = get_le32(bsp_ps_getp(ec, vm->ps, offs, 4));
}

/* return */
OPFUNC(op_return) {
	if (bsp_stk_getsize(vm) == 0) {
		vm->exit_code = 0;
		bsp_return(ec, BSP_RET_EXIT);
	}

	uint32_t pc_next = bsp_stk_pop(ec, vm);
	(void) bsp_ps_getp(ec, vm->ps, pc_next, 1);
	vm->pc_next = pc_next;
}

/* call addr_code */
OPFUNC(op_call) {
	bsp_stk_push(ec, vm, vm->pc_next);
	(void) bsp_ps_getp(ec, vm->ps, src[0], 1);
	vm->pc_next = src[0];
}

/* jump addr_code */
OPFUNC(op_jump) {
	(void) bsp_ps_getp(ec, vm->ps, src[0], 1);
	vm->pc_next = src[0];
}

/* <op>n?z #reg, addr */
#define OP_CONDFLOW(func, pred, target) \
	OPFUNC(func) { \
		if (!(src[0] pred)) \
			return; \
		return target(ec, vm, src + 1, dst); \
	}

OP_CONDFLOW(op_jumpz , == 0, op_jump)
OP_CONDFLOW(op_jumpnz, != 0, op_jump)
OP_CONDFLOW(op_callz , == 0, op_call)
OP_CONDFLOW(op_callnz, != 0, op_call)
OP_CONDFLOW(op_retz  , == 0, op_return)
OP_CONDFLOW(op_retnz , != 0, op_return)

/* if<cond> #reg, any, addr */
#define OP_CONDJUMP(func, op) \
	OPFUNC(func) { \
		if (!(src[0] op src[1])) \
			return; \
		(void) bsp_ps_getp(ec, vm->ps, src[2], 1); \
		vm->pc_next = src[2]; \
	}

OP_CONDJUMP(op_ifeq, ==)
OP_CONDJUMP(op_ifne, !=)
OP_CONDJUMP(op_iflt, < )
OP_CONDJUMP(op_ifle, <=)
OP_CONDJUMP(op_ifgt, > )
OP_CONDJUMP(op_ifge, >=)

/* [op] #dreg, any, any */
#define OP_ARITH_DIV(func, op) \
	OPFUNC(func) { \
		if (src[1] == 0) \
			bsp_die(ec, "attempt to divide by zero"); \
		*dst[0] = src[0] op src[1]; \
	}

#define OP_ARITH(func, op) \
	OPFUNC(func) { \
		*dst[0] = src[0] op src[1]; \
	}

OP_ARITH(op_add          , +)
OP_ARITH(op_subtract     , -)
OP_ARITH(op_multiply     , *)
OP_ARITH_DIV(op_divide   , /)
OP_ARITH_DIV(op_remainder, %)
OP_ARITH(op_and          , &)
OP_ARITH(op_or           , |)
OP_ARITH(op_xor          , ^)

OPFUNC(op_addcarry) {
	uint32_t result = src[0] + src[1];
	if (result < src[0])
		*dst[1] += 1;
	if (dst[0] == dst[1])
		return;
	*dst[0] = result;
}

OPFUNC(op_subborrow) {
	if (src[0] < src[1])
		*dst[1] -= 1;
	if (dst[0] == dst[1])
		return;
	*dst[0] = src[0] - src[1];
}

OPFUNC(op_longmul) {
	uint64_t result;
	result = (uint64_t)src[0] * (uint64_t)src[1];
	// do not change the order here!
	*dst[0] =  result       ;
	*dst[1] = (result >> 32);
}

OPFUNC(op_longmulacum) {
	uint64_t result = *dst[0] | (dst[1] != dst[0] ? (uint64_t)(*dst[1]) << 32 : 0);
	result += (uint64_t)src[0] * (uint64_t)src[1];
	// do not change the order here!
	*dst[1] = (result >> 32);
	*dst[0] =  result       ;
}

OPFUNC(op_bit_shift) {
	size_t count = src[1] & 0x1f;
	if (count == 0)
		return;

	switch (src[2]) {
	case BSP_SHIFT_SHL:
		*dst[0] = src[0] << count;
		return;
	case BSP_SHIFT_SHR:
		*dst[0] = src[0] >> count;
		return;
	case BSP_SHIFT_SAR:
		*dst[0] = ((int32_t)src[0]) >> count;
		return;
	case BSP_SHIFT_ROL:
		*dst[0] = rol32(src[0], count);
		return;
	default:
		abort();
	}
}

/* push any */
OPFUNC(op_push) {
	bsp_stk_push(ec, vm, src[0]);
}

/* pop #reg */
OPFUNC(op_pop) {
	*dst[0] = bsp_stk_pop(ec, vm);
}

OPFUNC(op_setstacksize) {
	bsp_stk_setsize(ec, vm, src[0]);
}

OPFUNC(op_getstacksize) {
	size_t size = bsp_stk_getsize(vm);
	if (size > 0xffffffff)
		size = 0xffffffff;
	*dst[0] = size;
}

noreturn static void bsp_die_stk(struct bsp_ec *ec, struct bsp_vm *vm, uint32_t pos, const char *errmsg) {
	size_t size = bsp_stk_getsize(vm);
	if (pos & 0x80000000)
		bsp_die(ec, "%s (relative index -%u; stack depth: %zu)", errmsg, -pos, size);
	else
		bsp_die(ec, "%s (relative index %u; stack depth: %zu)", errmsg, pos, size);
}

OPFUNC(op_stackread) {
	uint32_t *slot = bsp_stk_getslot(vm, src[0]);
	if (slot == NULL)
		bsp_die_stk(ec, vm, src[0], "attempt to read beyond the bounds of the stack");
	*dst[0] = *slot;
}

OPFUNC(op_stackwrite) {
	uint32_t *slot = bsp_stk_getslot(vm, src[0]);
	if (slot == NULL)
		bsp_die_stk(ec, vm, src[0], "attempt to write beyond the bounds of the stack");
	*slot = src[1];
}

OPFUNC(op_stackshift) {
	size_t size = bsp_stk_getsize(vm);
	size_t new_size = size;
	if (src[0] & 0x80000000) {
		new_size -= -src[0];
		if (new_size > size)
			bsp_die(ec, "attempt to shift stack beyond capacity (shift by -%u; stack depth: %zu)", -src[0], size);
	} else {
		new_size += src[0];
	}
	bsp_stk_setsize(ec, vm, new_size);
}

/* set #reg, any */
OPFUNC(op_set) {
	*dst[0] = src[0];
}

/* (inc|dec)rement #reg */
OPFUNC(op_increment) {
	*dst[0] += 1;
}

OPFUNC(op_decrement) {
	*dst[0] -= 1;
}

OPFUNC(op_getvariable) {
	/* sic, no error */
	*dst[0] = vm->regs[src[0] & 0xff];
}

/* get<size> #dst, addr */
/* get<size>(inc|dec) #dst, #addr */

#define OP_MOVM(func, b, n) \
	OPFUNC(func) { \
		*dst[0]  = get_le ## b(bsp_ps_getp(ec, vm->ps, src[0], n)); \
	}

#define OP_MOVS(func, b, n) \
	OPFUNC(func) { \
		*dst[0] = get_le ## b(bsp_ps_getp(ec, vm->ps, *dst[1], b / 8)); \
		if (dst[0] == dst[1]) \
			return; \
		*dst[1] += n; \
	}

OP_MOVM(op_getbyte       , 8,  1)
OP_MOVS(op_getbyteinc    , 8, +1)
OP_MOVS(op_getbytedec    , 8, -1)

OP_MOVM(op_gethalfword   , 16,  2)
OP_MOVS(op_gethalfwordinc, 16, +2)
OP_MOVS(op_gethalfworddec, 16, -2)

OP_MOVM(op_getword       , 32,  4)
OP_MOVS(op_getwordinc    , 32, +4)
OP_MOVS(op_getworddec    , 32, -4)

/* length #reg */
OPFUNC(op_length) {
	off_t len = bsp_io_length(ec, vm->io);
	if (len > 0xffffffff)
		bsp_die(ec, "the file is larger than 4 GiB");
	*dst[0] = len;
}

/* checksha1 #reg, addr */
OPFUNC(op_checksha1) {
	const uint8_t *target_sha1 = bsp_ps_getp(ec, vm->ps, src[0], 20);
	const uint8_t *actual_sha1 = bsp_io_sha1(ec, vm->io);

	*dst[0] = 0;
	for (size_t i = 0; i < 20; ++i) {
		if (target_sha1[i] == actual_sha1[i])
			continue;
		*dst[0] |= 1 << i;
	}
}

#define OP_READFUNC(func, b) \
	OPFUNC(func) { \
		uint8_t datum[b / 8]; \
		if (bsp_io_read(ec, vm->io, datum, sizeof(datum)) < sizeof(datum)) \
			bsp_die(ec, "attempt to read beyond end of file"); \
		*dst[0] = get_le ## b (datum); \
	}

#define OP_PEEKFUNC(func, b) \
	OPFUNC(func) { \
		uint8_t datum[b / 8]; \
		if (bsp_io_pread(ec, vm->io, datum, sizeof(datum), bsp_io_tell(ec, vm->io)) < sizeof(datum)) \
			bsp_die(ec, "attempt to read beyond end of file"); \
		*dst[0] = get_le ## b (datum); \
	}

#define OP_WRITEFUNC(func, b) \
	OPFUNC(func) { \
		uint8_t datum[b / 8]; \
		put_le ## b (datum, src[0]); \
		bsp_io_write(ec, vm->io, &datum, sizeof(datum)); \
	}

OP_READFUNC(op_readbyte       , 8)
OP_READFUNC(op_readhalfword   , 16)
OP_READFUNC(op_readword       , 32)

OP_PEEKFUNC(op_getfilebyte    , 8)
OP_PEEKFUNC(op_getfilehalfword, 16)
OP_PEEKFUNC(op_getfileword    , 32)

OP_WRITEFUNC(op_writebyte     , 8)
OP_WRITEFUNC(op_writehalfword , 16)
OP_WRITEFUNC(op_writeword     , 32)

/* ipspatch #reg, addr */
OPFUNC(op_ipspatch) {
	static const char ips_magic[5] = "PATCH";

	uint32_t addr = src[0];

	if (memcmp(bsp_ps_getp(ec, vm->ps, addr, sizeof(ips_magic)), ips_magic, sizeof(ips_magic)))
		bsp_die(ec, "IPS magic mismatch");
	addr += sizeof(ips_magic);

	for (;;) {
		uint32_t offset = get_be24(bsp_ps_getp(ec, vm->ps, addr, 3));
		addr += 3;

		if (offset == 0x454f46)
			break;

		uint16_t length = get_be16(bsp_ps_getp(ec, vm->ps, addr, 2));
		addr += 2;

		if (length == 0) {
			uint16_t count = get_be16(bsp_ps_getp(ec, vm->ps, addr, 2));
			uint8_t datum = *bsp_ps_getp(ec, vm->ps, addr + 2, 1);
			addr += 3;

			bsp_io_pfill(ec, vm->io,
				datum, 1, count,
				bsp_io_tell(ec, vm->io) + offset
			);
		} else {
			bsp_io_pwrite(ec, vm->io,
				bsp_ps_getp(ec, vm->ps, addr, length), length,
				bsp_io_tell(ec, vm->io) + offset
			);
			addr += length;
		}
	}

	*dst[0] = addr;
}

/* bsppatch #reg, addr, len */
OPFUNC(op_bsppatch) {
	if (!src[1])
		bsp_die(ec, "child patch space is empty");

	struct bsp_ps child_ps;
	child_ps.space = bsp_ps_getp(ec, vm->ps, src[0], src[1]);
	child_ps.limit = src[1] - 1;

	struct bsp_vm child_vm;
	bsp_init(ec, &child_vm, &child_ps, vm->io);

	child_vm.top = vm->top;
	child_vm.parent = vm;
	child_vm.nest_level = vm->nest_level + 1;
	child_vm.cb = vm->cb;
	child_vm.cookie = vm->cookie;

	struct bsp_ec child_ec;
	bsp_ret_t ret = bsp_try(&child_ec);

	if (ret) {
		bsp_fini(&child_vm);
		bsp_rethrow(ec, &child_ec, ret);
	}

	*dst[0] = bsp_run(&child_ec, &child_vm);
	bsp_fini(&child_vm);
}

/* xordata addr, len */
OPFUNC(op_xordata) {
	uint32_t length = src[1];
	const uint8_t *datap = bsp_ps_getp(ec, vm->ps, src[0], length);
	uint8_t buffer[2048];

	off_t offset = bsp_io_tell(ec, vm->io);

	while (length > 0) {
		size_t got = bsp_io_pread(ec, vm->io, buffer, min32(length, sizeof(buffer)), offset);
		if (got == 0) {
			bsp_io_pwrite(ec, vm->io, datap, length, offset);
			offset += length;
			break;
		}

		for (size_t i = 0; i < got; ++i) {
			buffer[i] ^= *datap++;
		}

		bsp_io_pwrite(ec, vm->io, buffer, got, offset);
		length -= got;
		offset += got;
	}

	bsp_io_seek(ec, vm->io, offset, BSP_WHENCE_SET);
}

/* writedata addr, len */
OPFUNC(op_writedata) {
	uint32_t length = src[1];
	const uint8_t *datap = bsp_ps_getp(ec, vm->ps, src[0], length);
	bsp_io_write(ec, vm->io, datap, length);
}

/* fill* value, addr, len */
#define OP_FILL(func, nb) \
	OPFUNC(func) { \
		size_t count = src[0]; \
		uint32_t datum = src[1]; \
		bsp_io_fill(ec, vm->io, datum, nb, count); \
	}

OP_FILL(op_fillbyte    , 1)
OP_FILL(op_fillhalfword, 2)
OP_FILL(op_fillword    , 4)

/* seek{fwd|back|end} any */
#define OP_SEEK(func, whence) \
	OPFUNC(func) { \
		bsp_io_seek(ec, vm->io, src[0], whence); \
	}

OP_SEEK(op_seek    , BSP_WHENCE_SET);
OP_SEEK(op_seekfwd , BSP_WHENCE_FORWARD);
OP_SEEK(op_seekback, BSP_WHENCE_REWIND);
OP_SEEK(op_seekend , BSP_WHENCE_END);

OPFUNC(op_lockpos) {
	bsp_io_lock(ec, vm->io, true);
}

OPFUNC(op_unlockpos) {
	bsp_io_lock(ec, vm->io, false);
}

OPFUNC(op_pushpos) {
	off_t pos = bsp_io_tell(ec, vm->io);
	if (pos > 0xffffffff)
		bsp_die(ec, "offset larger than 4 GiB");
	bsp_stk_push(ec, vm, pos);
}

OPFUNC(op_poppos) {
	bsp_io_seek(ec, vm->io, bsp_stk_pop(ec, vm), SEEK_SET);
}

OPFUNC(op_pos) {
	off_t pos = bsp_io_tell(ec, vm->io);
	if (pos > 0xffffffff)
		bsp_die(ec, "offset larger than 4 GiB");
	*dst[0] = pos;
}

/* truncate any */
OPFUNC(op_truncate) {
	bsp_io_truncate(ec, vm->io, src[0]);
}

/* truncatepos */
OPFUNC(op_truncatepos) {
	bsp_io_truncate(ec, vm->io, bsp_io_tell(ec, vm->io));
}

#define MENU_MALLOC_THRESHOLD 0x100

/* menu #reg, addr */
OPFUNC(op_menu) {
	uint32_t strtab_off = src[0];
	uint32_t count = 0;

	// verify first
	for (;;) {
		uint32_t off = get_le32(bsp_ps_getp(ec, vm->ps, strtab_off, 4));
		if (off == 0xffffffff)
			break;
		size_t len;
		const char *item = bsp_ps_getsz(ec, vm->ps, off, &len);
		validate_utf8(ec, item, len);
		strtab_off += 4;
		count++;
	}

	if (count == 0) {
		// this is what the spec requires to happen
		// I am quite surprised it doesn't prescribe generating a fatal error instead
		*dst[0] = 0xffffffff;
		return;
	}

	if (vm->cb == NULL || vm->cb->menu == NULL)
		bsp_die(ec, "no menu callback");

	size_t block_size = count * (sizeof(size_t) + sizeof(const char *));
	void *block;
	if (block_size >= MENU_MALLOC_THRESHOLD) {
		block = malloc(block_size);
	} else {
		block = alloca(block_size);
	}

	static_assert(sizeof(const char *) >= alignof(size_t), "allocation below may fail");

	const char **items = (const char **)block;
	size_t *lens = (size_t *)((char *)block + count * sizeof(const char *));

	strtab_off = src[0];
	for (int i = 0; i < count; ++i) {
		uint32_t off = get_le32(bsp_ps_getp(ec, vm->ps, strtab_off, 4));
		items[i] = bsp_ps_getsz(ec, vm->ps, off, &lens[i]);
		strtab_off += 4;
	}

	bsp_ret_t ret;
	struct bsp_ec child_ec;
	if ((ret = bsp_try(&child_ec))) {
		if (block_size >= MENU_MALLOC_THRESHOLD)
			free(block);
		bsp_rethrow(ec, &child_ec, ret);
	}

	uint32_t choice = (*vm->cb->menu)(&child_ec, vm, count, items, lens);

	if (block_size >= MENU_MALLOC_THRESHOLD)
		free(block);

	*dst[0] = choice;
}

const bsp_ophandler_t bsp_ophandlers[] = {
#define OPCODE_DEF(b, _0, hand, _1, _2, _3) [b] = hand,
#include "opdef.h"
#undef OPCODE_DEF
};
