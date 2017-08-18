#include "buf.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

void bsp_buf_init(struct bsp_ec *ec, struct bsp_vm *vm) {
	vm->_buf_used = 0;
	vm->_buf_alloc = 512;
	vm->_buf = malloc(vm->_buf_alloc * sizeof(*vm->_buf));
	if (vm->_buf == NULL)
		bsp_die(ec, "malloc(buf, %u): %s", vm->_buf_alloc, strerror(errno));
}

void bsp_buf_fini(struct bsp_vm *vm) {
	free(vm->_buf);
	vm->_buf = NULL;
}

void bsp_buf_push(struct bsp_ec *ec, struct bsp_vm *vm, const char *data, size_t length) {
	if ((vm->_buf_used + length) < vm->_buf_used)
		bsp_die(ec, "buffer overflow");

	if ((vm->_buf_used + length) > vm->_buf_alloc) {
		size_t new_alloc = vm->_buf_alloc;
		while ((vm->_buf_used + length) > new_alloc) {
			if (new_alloc * 2 < new_alloc) {
				new_alloc = vm->_buf_used + length;
				break;
			}
			new_alloc *= 2;
		}

		void *new_buf = realloc(vm->_buf, new_alloc);
		if (new_buf == NULL)
			bsp_die(ec, "realloc(buf, %u): %s", new_alloc, strerror(errno));
		vm->_buf = new_buf;
		vm->_buf_alloc = new_alloc;
	}

	memcpy(vm->_buf + vm->_buf_used, data, length);
	vm->_buf_used += length;
}

void bsp_buf_clear(struct bsp_ec *ec, struct bsp_vm *vm) {
	size_t buf_limit = vm->_buf_used + (vm->_buf_used >> 1);
	if (vm->_buf_alloc > buf_limit) {
		/* shrink the buffer */
		free(vm->_buf);
		vm->_buf_alloc = buf_limit;
		vm->_buf = malloc(buf_limit);
		if (vm->_buf == NULL)
			bsp_die(ec, "malloc(buf, %u): %s", buf_limit, strerror(errno));
	}
	vm->_buf_used = 0;
}
