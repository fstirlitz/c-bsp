#define _POSIX_C_SOURCE 200809L

#include "ps.h"
#include "util.h"

#include <string.h>
#include <stdlib.h>

const uint8_t *bsp_ps_getp(struct bsp_ec *ec, const struct bsp_ps *ps, uint32_t addr, uint32_t size) {
	if ((addr + size - 1) < addr) {
		bsp_die(ec, "pointer overflow: "
			"0x%x + 0x%x", addr, size);
	}

	if (addr > ps->limit) {
		bsp_die(ec, "attempt to access data beyond end of BSP space: "
			"0x%x > 0x%x", addr, ps->limit);
	}

	if (size && (addr + size - 1) > ps->limit) {
		bsp_die(ec, "attempt to access data overflowing beyond end of BSP space: "
			"0x%x + 0x%x - 1 = 0x%x > 0x%x",
			addr, size, addr + size - 1, ps->limit);
	}

	return ps->space + addr;
}

const char *bsp_ps_getsz(struct bsp_ec *ec, const struct bsp_ps *ps, uint32_t addr, size_t *len) {
	if (addr > ps->limit) {
		bsp_die(ec, "attempt to access data beyond end of BSP space: "
			"0x%x > 0x%x", addr, ps->limit);
	}

	const char *p = (const char *)ps->space + addr;
	*len = strnlen(p, ps->limit - addr);
	return p;
}

#define FETCHER(b) \
	inline static uint32_t fetch_op ## b(struct bsp_ec *ec, const struct bsp_ps *ps, uint32_t *pc) { \
		const uint8_t *p = bsp_ps_getp(ec, ps, *pc, b / 8); \
		*pc += b / 8; \
		return get_le ## b(p); \
	}

FETCHER(8)
FETCHER(16)
FETCHER(32)

#undef FETCHER

#define BSP_OPDS(a, b, c, d) ( 010000 \
	| ((BSP_OPD_ ## d) << 9) \
	| ((BSP_OPD_ ## c) << 6) \
	| ((BSP_OPD_ ## b) << 3) \
	|  (BSP_OPD_ ## a)       )
#define BSP_OPD_AT(ops, i) (bsp_optype_t)( ((ops) >> (i * 3)) & 0x7 )

typedef enum {
	BSP_OPDS_UNDEF = 0,
	BSP_OPDS_SHIFT = 1,
	BSP_OPDS_NONE  = BSP_OPDS(NONE, NONE, NONE, NONE),
} bsp_optypes_t;

static const uint32_t operands[] = {
#define OPCODE_DEF(b, _0, _1, opds, _2, _3) [b] = opds,
#include "opdef.h"
#undef OPCODE_DEF
};

size_t bsp_ps_fetchop(struct bsp_ec *ec, const struct bsp_ps *ps, uint32_t pc, struct bsp_opcode *opc) {
	uint32_t pc0 = pc;

	uint_fast8_t opind = 0;
	opc->opcode = fetch_op8(ec, ps, &pc);

	if (opc->opcode >= COUNT(operands))
		bsp_die(ec, "undefined opcode 0x%02x", opc->opcode);

	bsp_optypes_t optypes = operands[opc->opcode];

	switch (optypes) {

	case BSP_OPDS_UNDEF:
		bsp_die(ec, "undefined opcode 0x%02x", opc->opcode);

	case BSP_OPDS_SHIFT: {
		uint_fast8_t spec = fetch_op8(ec, ps, &pc);

		opc->optyp[opind] = BSP_OPD_MREG;
		opc->opval[opind] = fetch_op8(ec, ps, &pc);
		opind++;

		if (spec & BSP_SHIFT_REG) {
			opc->optyp[opind] = BSP_OPD_RREG;
			opc->opval[opind] = fetch_op8(ec, ps, &pc);
		} else {
			opc->optyp[opind] = BSP_OPD_IMM32;
			opc->opval[opind] = fetch_op32(ec, ps, &pc);
		}
		opind++;

		if (spec & BSP_SHIFT_MASK_COUNT) {
			opc->optyp[opind] = BSP_OPD_IMM8;
			opc->opval[opind] = spec & BSP_SHIFT_MASK_COUNT;
		} else {
			opc->optyp[opind] = BSP_OPD_RREG;
			opc->opval[opind] = fetch_op8(ec, ps, &pc);
		}
		opind++;

		opc->optyp[opind] = BSP_OPD_NONE; // hide it from disassembly
		opc->opval[opind] = spec & BSP_SHIFT_MASK_TYPE;

		break;
	}

	default:
		for (opind = 0; opind < BSP_OPNUM; opind++) {
			switch (opc->optyp[opind] = BSP_OPD_AT(optypes, opind)) {
			case BSP_OPD_NONE:
				break;
			case BSP_OPD_IMM8:
				opc->opval[opind] = fetch_op8(ec, ps, &pc);
				break;
			case BSP_OPD_IMM16:
				opc->opval[opind] = fetch_op16(ec, ps, &pc);
				break;
			case BSP_OPD_IMM32:
				opc->opval[opind] = fetch_op32(ec, ps, &pc);
				break;
			case BSP_OPD_RREG:
			case BSP_OPD_MREG:
			case BSP_OPD_WREG:
				opc->opval[opind] = fetch_op8(ec, ps, &pc);
				break;
			default:
				abort();
			}
		}

	}

	return pc - pc0;
}
