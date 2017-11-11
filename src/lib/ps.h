#ifndef BSP_H_PS
#define BSP_H_PS

#include <stddef.h>
#include <stdint.h>

#include "ec.h"

// Patch space.
struct bsp_ps {
	const uint8_t *space;
	uint32_t size;
};

const uint8_t *bsp_ps_getp(struct bsp_ec *ec, const struct bsp_ps *ps, uint32_t addr, uint32_t size);
const char *bsp_ps_getsz(struct bsp_ec *ec, const struct bsp_ps *ps, uint32_t addr, size_t *len);

typedef enum {
	BSP_OPD_NONE , // no operand
	BSP_OPD_IMM8 , // immediate 8-bit operand
	BSP_OPD_IMM16, // immediate 16-bit operand
	BSP_OPD_IMM32, // immediate 32-bit operand
	BSP_OPD_RREG , // read-only register operand
	BSP_OPD_WREG , // write-only register operand
	BSP_OPD_MREG , // read-write register operand
} bsp_optype_t;

#define BSP_OPNUM 4

struct bsp_opcode {
	uint32_t      opval[BSP_OPNUM];
	bsp_optype_t  optyp[BSP_OPNUM];
	uint8_t       opcode;
};

enum {
	BSP_SHIFT_MASK_COUNT = 0x1f,
	BSP_SHIFT_MASK_TYPE  = 0x60,

	/* shift type */
	BSP_SHIFT_SHL        = 0x00,
	BSP_SHIFT_SHR        = 0x20,
	BSP_SHIFT_ROL        = 0x40,
	BSP_SHIFT_SAR        = 0x60,

	/* source operand is register */
	BSP_SHIFT_REG        = 0x80,
};

size_t bsp_ps_fetchop(struct bsp_ec *, const struct bsp_ps *, uint32_t pc, struct bsp_opcode *opc);

#endif
