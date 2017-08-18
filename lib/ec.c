#define _GNU_SOURCE

#include "ec.h"

#include <stdio.h>
#include <stdlib.h>

void bsp_ec_clear(struct bsp_ec *ec) {
	if (ec->fatal_msg == NULL)
		return;
	free((void *)ec->fatal_msg);
	ec->fatal_msg = NULL;
}

noreturn void bsp_return(struct bsp_ec *ec, bsp_ret_t ret) {
	longjmp(ec->_jmp_buf, ret);
}

noreturn void bsp_rethrow(struct bsp_ec *ec, struct bsp_ec *child_ec, bsp_ret_t ret) {
	if (ec == NULL)
		abort();

	ec->fatal_msg = child_ec->fatal_msg;
	bsp_return(ec, ret);
}

noreturn void bsp_diev(struct bsp_ec *ec, const char *fmt, va_list ap) {
	if (ec == NULL)
		abort();
	if (ec->fatal_msg != NULL)
		abort();

	char *msg;
	if (vasprintf(&msg, fmt, ap) == -1)
		msg = NULL;
	ec->fatal_msg = msg;

	bsp_return(ec, BSP_RET_FATAL);
}

noreturn void bsp_die(struct bsp_ec *ec, const char *fmt, ...) {
	va_list ap;

	va_start(ap, fmt);
	bsp_diev(ec, fmt, ap);
	va_end(ap);
}
