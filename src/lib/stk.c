#include "stk.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

void bsp_stk_init(struct bsp_ec *ec, struct bsp_vm *vm) {
	vm->_stk_used = 0;
	vm->_stk_alloc = 32;
	vm->_stk = malloc(vm->_stk_alloc * sizeof(*vm->_stk));
	if (vm->_stk == NULL)
		bsp_die(ec, "malloc(stk, %u items): %s", vm->_stk_alloc, strerror(errno));
}

void bsp_stk_fini(struct bsp_vm *vm) {
	free(vm->_stk);
	vm->_stk = NULL;
}

void bsp_stk_push(struct bsp_ec *ec, struct bsp_vm *vm, uint32_t value) {
	if (vm->_stk_used == vm->_stk_alloc) {
		size_t extra = vm->_stk_alloc;
		size_t new_alloc;
		do {
			if (extra == 0)
				bsp_die(ec, "stack size overflow");
			new_alloc = vm->_stk_alloc + extra;
			extra >>= 1;
		} while (new_alloc * sizeof(*vm->_stk) < vm->_stk_alloc * sizeof(*vm->_stk));

		void *new_stk = realloc(vm->_stk, new_alloc * sizeof(*vm->_stk));
		if (new_stk == NULL)
			bsp_die(ec, "realloc(stk, %u items): %s", new_alloc, strerror(errno));
		vm->_stk = new_stk;
		vm->_stk_alloc = new_alloc;
	}
	vm->_stk[vm->_stk_used++] = value;
}

uint32_t bsp_stk_pop(struct bsp_ec *ec, struct bsp_vm *vm) {
	if (vm->_stk_used == 0)
		bsp_die(ec, "stack underflow");
	return vm->_stk[--vm->_stk_used];
}

void bsp_stk_setsize(struct bsp_ec *ec, struct bsp_vm *vm, size_t size) {
	if (size > vm->_stk_used) {
		if (size * sizeof(*vm->_stk) < size)
			bsp_die(ec, "stack size overflow");

		if (size > vm->_stk_alloc) {
			size_t new_alloc = vm->_stk_alloc;
			while (size > new_alloc) {
				if (new_alloc * 2 < new_alloc) {
					new_alloc = size;
					break;
				}
				new_alloc *= 2;
			}

			void *new_stk = realloc(vm->_stk, new_alloc * sizeof(*vm->_stk));
			if (new_stk == NULL)
				bsp_die(ec, "realloc(stk, %u items): %s", new_alloc, strerror(errno));
			vm->_stk = new_stk;
			vm->_stk_alloc = new_alloc;
		}

		memset(vm->_stk + vm->_stk_used, 0, (size - vm->_stk_used) * sizeof(*vm->_stk));
	}
	vm->_stk_used = size;
}

size_t bsp_stk_getsize(struct bsp_vm *vm) {
	return vm->_stk_used;
}

uint32_t *bsp_stk_getslot(struct bsp_vm *vm, uint32_t pos) {
	size_t size = bsp_stk_getsize(vm);
	size_t i = (pos & 0x80000000) ? -(pos + 1) : size - (pos + 1);
	if (i >= size)
		return NULL;
	return &vm->_stk[i];
}
