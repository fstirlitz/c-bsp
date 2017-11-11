#ifndef BSP_H_BUF
#define BSP_H_BUF

#include "vm.h"

void bsp_buf_init(struct bsp_ec *ec, struct bsp_vm *vm);
void bsp_buf_push(struct bsp_ec *ec, struct bsp_vm *vm, const char *data, size_t length);
void bsp_buf_clear(struct bsp_ec *ec, struct bsp_vm *vm);
void bsp_buf_fini(struct bsp_vm *vm);

#endif
