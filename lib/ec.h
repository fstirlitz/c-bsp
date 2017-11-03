#ifndef BSP_H_EC
#define BSP_H_EC

#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <stdnoreturn.h>

typedef enum {
	BSP_RET_NONE,
	BSP_RET_OK,
	BSP_RET_EXIT,
	BSP_RET_USER_ABORT,
	BSP_RET_FATAL,
	BSP_RET_SKIP,
} bsp_ret_t;

struct bsp_ec {
	/* public: fatal error message */
	const char *fatal_msg;

	/* private */
	jmp_buf _jmp_buf;
};

inline static struct bsp_ec *_bsp_try(struct bsp_ec *ec) {
	ec->fatal_msg = NULL;
	return ec;
}

#define bsp_try(ec) ((bsp_ret_t)setjmp(_bsp_try(ec)->_jmp_buf))
noreturn void bsp_return(struct bsp_ec *ec, bsp_ret_t);
noreturn void bsp_rethrow(struct bsp_ec *ec, struct bsp_ec *child_ec, bsp_ret_t ret);
noreturn void bsp_die(struct bsp_ec *ec, const char *fmt, ...);
void bsp_ec_clear(struct bsp_ec *ec);

#endif
