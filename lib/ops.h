#ifndef BSP_H_OPS
#define BSP_H_OPS

#include <stdint.h>

#include "ec.h"
#include "vm.h"
#include "io.h"

typedef void (*bsp_ophandler_t)(struct bsp_ec *, struct bsp_vm *, struct bsp_io *, const uint32_t [], uint32_t *[]);

extern const bsp_ophandler_t bsp_ophandlers[];

#endif
