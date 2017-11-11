#include "buf.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include "util.h"

void bsp_buf_init(struct bsp_ec *ec, struct bsp_vm *vm) {
	vm->_buf_used = 0;
	vm->_buf_alloc = 128;
	vm->_buf = malloc(vm->_buf_alloc * sizeof(*vm->_buf));
	if (vm->_buf == NULL)
		bsp_die(ec, "malloc(buf, %u): %s", vm->_buf_alloc, strerror(errno));
}

void bsp_buf_fini(struct bsp_vm *vm) {
	free(vm->_buf);
	vm->_buf = NULL;
}

void bsp_buf_push(struct bsp_ec *ec, struct bsp_vm *vm, const char *data, size_t length) {
	if (!length)
		return;

	if ((vm->_buf_used + length) > vm->_buf_alloc) {
		void *buf = grow_alloc(vm->_buf, &vm->_buf_alloc, length, 1);
		if (buf == NULL)
			bsp_die(ec, "cannot allocate %zu more buffer bytes: %s", length, strerror(errno));
		vm->_buf = buf;
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
