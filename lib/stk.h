#ifndef BSP_H_STK
#define BSP_H_STK

#include "vm.h"

void bsp_stk_init(struct bsp_ec *ec, struct bsp_vm *vm);
void bsp_stk_fini(struct bsp_vm *vm);
void bsp_stk_push(struct bsp_ec *ec, struct bsp_vm *vm, uint32_t value);
uint32_t bsp_stk_pop(struct bsp_ec *ec, struct bsp_vm *vm);
void bsp_stk_setsize(struct bsp_ec *ec, struct bsp_vm *vm, size_t size);
size_t bsp_stk_getsize(struct bsp_vm *vm);
uint32_t *bsp_stk_getslot(struct bsp_vm *vm, uint32_t pos);

#endif
