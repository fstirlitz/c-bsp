#include "dis.h"

#include "util.h"

static const char *mnemonics[] = {
#define OPCODE_DEF(b, mnem, _0, _1, _2, _3) [b] = mnem,
#include "opdef.h"
#undef OPCODE_DEF
};

static uint32_t semantics[] = {
#define OPCODE_DEF(b, _0, _1, _2, sems, _3) [b] = sems,
#define BSP_SEMS(a, b, c, d) ( \
	(BSP_OPSEM_ ## a      ) | \
	(BSP_OPSEM_ ## b <<  8) | \
	(BSP_OPSEM_ ## c << 16) | \
	(BSP_OPSEM_ ## d << 24)   )
#include "opdef.h"
#undef BSP_SEMS
#undef OPCODE_DEF
};

static uint8_t flags[] = {
#define OPCODE_DEF(b, _0, _1, _2, _3, fl) [b] = fl,
#include "opdef.h"
#undef OPCODE_DEF
};

const char *bsp_op_get_mnemonic(const struct bsp_opcode *opc) {
	if (opc->opcode >= COUNT(mnemonics))
		return NULL;

	const char *result = mnemonics[opc->opcode];
	if (result != NULL)
		return result;

	if (opc->opcode == 0xab) {
		switch (opc->opval[3]) {
		case BSP_SHIFT_SHL:
			return "shiftleft";
		case BSP_SHIFT_SHR:
			return "shiftright";
		case BSP_SHIFT_ROL:
			return "rotateleft";
		case BSP_SHIFT_SAR:
			return "shiftrightarith";
		}
	}

	return NULL;
}

bsp_opsems_t bsp_op_get_sems(const struct bsp_opcode *opc) {
	if (opc->opcode >= COUNT(semantics))
		return 0;
	return semantics[opc->opcode];
}

bsp_opflags_t bsp_op_get_flags(const struct bsp_opcode *opc) {
	if (opc->opcode >= COUNT(flags))
		return 0;
	return flags[opc->opcode];
}
