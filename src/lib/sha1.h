#ifndef BSP_H_SHA1
#define BSP_H_SHA1

#include <stddef.h>
#include <stdint.h>

struct bsp_sha1_state {
	char chunk[64];
	uint64_t length;
	uint32_t h[5];
	uint_fast8_t chunk_used;
};

void bsp_sha1_init(struct bsp_sha1_state *);
void bsp_sha1_update(struct bsp_sha1_state *, const char *, size_t);
void bsp_sha1_finish(struct bsp_sha1_state *, uint8_t *result);

#endif
