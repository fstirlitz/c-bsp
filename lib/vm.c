#include "vm.h"

#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include <setjmp.h>
#include <errno.h>

#include "util.h"
#include "stk.h"
#include "buf.h"
#include "ops.h"

/* memory */
void bsp_init(struct bsp_ec *ec, struct bsp_vm *vm, const struct bsp_ps *ps, struct bsp_io *io) {
	memset(vm->regs, 0, sizeof(vm->regs));

	vm->ps = ps;
	vm->io = io;

	vm->pc = 0;
	vm->pc_next = 0;

	vm->cookie = NULL;
	vm->cb = NULL;

	bsp_stk_init(ec, vm);
	bsp_buf_init(ec, vm);

	vm->nest_level = 0;
	vm->parent = NULL;
	vm->top = vm;
}

void bsp_fini(struct bsp_vm *vm) {
	bsp_stk_fini(vm);
	bsp_buf_fini(vm);
}

static void bsp_exec_step(struct bsp_ec *ec, struct bsp_vm *vm) {
	vm->pc = vm->pc_next;

	/* fetch/decode */
	if (vm->cb != NULL && vm->cb->fetch != NULL) {
		(*vm->cb->fetch)(ec, vm);
	}

	struct bsp_opcode opc;

	size_t s = bsp_ps_fetchop(ec, vm->ps, vm->pc, &opc);
	vm->pc_next = vm->pc + s;

	bsp_ophandler_t handler = bsp_ophandlers[opc.opcode];

	/* load registers */
	uint_fast8_t si = 0, di = 0;
	uint32_t src[BSP_OPNUM], *dst[BSP_OPNUM];
	for (uint_fast8_t opind = 0; opind < BSP_OPNUM; ++opind) {
		switch (opc.optyp[opind]) {
		default:
			src[si++] = opc.opval[opind];
			break;
		case BSP_OPD_RREG:
			src[si++] = vm->regs[opc.opval[opind]];
			break;
		case BSP_OPD_MREG:
		case BSP_OPD_WREG:
			dst[di++] = &vm->regs[opc.opval[opind]];
			break;
		}
	}

	/* execute */
	if (vm->cb != NULL && vm->cb->exec != NULL) {
		vm->cb->exec(ec, vm, &opc);
	}
	(*handler)(ec, vm, vm->io, src, dst);
	if (vm->cb != NULL && vm->cb->postexec != NULL) {
		vm->cb->postexec(ec, vm, &opc);
	}
}

uint32_t bsp_run(struct bsp_ec *ec, struct bsp_vm *vm) {
	struct bsp_ec local_ec;
	bsp_ret_t ret = bsp_try(&local_ec);

	if (ret) {
		if (ret == BSP_RET_EXIT)
			return vm->exit_code;
		if (vm->cb != NULL && vm->cb->fatal != NULL)
			vm->cb->fatal(vm, ret, &local_ec);
		bsp_rethrow(ec, &local_ec, ret);
	}

	for (;;) {
		bsp_exec_step(&local_ec, vm);
	}
}
