#ifndef BSP_H_VM
#define BSP_H_VM

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>

#include "ec.h"
#include "ps.h"
#include "io.h"

struct bsp_vm;

struct bsp_cb {
	uint_fast32_t (*menu)(struct bsp_ec *, struct bsp_vm *, uint_fast32_t, const char *[], const size_t []);
	void (*print)(struct bsp_ec *, struct bsp_vm *, const char *, size_t);
	void (*fetch)(struct bsp_ec *, struct bsp_vm *);
	void (*exec)(struct bsp_ec *, struct bsp_vm *, struct bsp_opcode *);
	void (*postexec)(struct bsp_ec *, struct bsp_vm *, struct bsp_opcode *);
	void (*fatal)(struct bsp_vm *, bsp_ret_t, struct bsp_ec *ec);
};

struct bsp_vm {
	/* public: callbacks */
	struct bsp_cb *cb;

	/* public: opaque data */
	void *cookie;

	/* public: exit protocol */
	uint32_t exit_code;

	/* semi-public: nesting protocol */
	struct bsp_vm *parent, *top;
	uint16_t nest_level;

	/* semi-public: resources */
	const struct bsp_ps *ps;
	struct bsp_io *io;

	/* semi-public: registers */
	uint32_t regs[256];

	/* semi-public: program counter of last fetched instruction */
	uint32_t pc;

	/* semi-public: program counter of next instruction to execute */
	uint32_t pc_next;

	/* private: */
	size_t _stk_alloc, _stk_used;
	uint32_t *_stk;

	size_t _buf_alloc, _buf_used;
	char *_buf;
};

void bsp_init(struct bsp_ec *, struct bsp_vm *, const struct bsp_ps *, struct bsp_io *);
void bsp_fini(struct bsp_vm *);
uint32_t bsp_run(struct bsp_ec *, struct bsp_vm *);

#endif
