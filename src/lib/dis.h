#ifndef BSP_H_DIS
#define BSP_H_DIS

#include "ps.h"

typedef enum {
	BSP_OPSEM_ARITH             = 0x00,   // no particular semantics
	BSP_OPSEM_STACK             = 0x01,   // stack index
	BSP_OPSEM_STACKW            = 0x02,   // stack index that is written to
	BSP_OPSEM_STACKR            = 0x03,   // stack index that is read from
	BSP_OPSEM_LENGTH            = 0x04,   // length of data contained in patch space
	BSP_OPSEM_JUMPIND           = 0x05,   // jump table index
	BSP_OPSEM_COND              = 0x06,   // checked for being zero
	BSP_OPSEM_POS               = 0x07,   // position
	BSP_OPSEM_USV               = 0x08,   // Unicode scalar value
	BSP_OPSEM_SHIFT             = 0x09,   // shift/rotate count
	BSP_OPSEM_DIVISOR           = 0x0a,   // divisor

	BSP_OPSEM_PTR_DATA          = 0x10,   // address of not-otherwise-specified data
	BSP_OPSEM_PTR_DATA8         = 0x11,   // address of a byte
	BSP_OPSEM_PTR_DATA16        = 0x12,   // address of a halfword
	BSP_OPSEM_PTR_DATA32        = 0x13,   // address of a word
	BSP_OPSEM_PTR_CODE          = 0x14,   // jump/call target
	BSP_OPSEM_PTR_STR           = 0x15,   // address of a string
	BSP_OPSEM_PTR_SHA1          = 0x16,   // address of a SHA-1 hash literal
	BSP_OPSEM_PTR_IPS           = 0x17,   // address of an embedded IPS patch
	BSP_OPSEM_PTR_BSP           = 0x18,   // address of an embedded BSP patch
	BSP_OPSEM_PTR_MENU          = 0x19,   // address of menu data
} bsp_opsem_t;

#define BSP_OPSEM_AT(sems, i) ((bsp_opsem_t)(((sems) >> (8 * i)) & 0xff))

typedef uint_fast32_t bsp_opsems_t;

#define BSP_OPFLAG_STOPS_FLOW     0x01   // control flow does not extend past this instruction
#define BSP_OPFLAG_JUMP_TABLE     0x02   // instruction is followed by a jump table
#define BSP_OPFLAG_POP            0x04   // instruction may remove an item from the top of the stack
#define BSP_OPFLAG_CALL           0x08   // instruction may redirect control flow, but is expected to return later
#define BSP_OPFLAG_RDPOS          0x10   // reads file position
#define BSP_OPFLAG_WRPOS          0x20   // may modify file position
#define BSP_OPFLAG_TIGHT_LOOP     0x40   // this instruction may redirect control flow, but does not modify state

typedef uint_fast8_t bsp_opflags_t;

const char *bsp_op_get_mnemonic(const struct bsp_opcode *opc);
bsp_opsems_t bsp_op_get_sems(const struct bsp_opcode *opc);
bsp_opflags_t bsp_op_get_flags(const struct bsp_opcode *opc);

#endif
