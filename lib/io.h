#ifndef BSP_H_IO
#define BSP_H_IO

#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>

#include "ec.h"

struct bsp_io {
	/* public */
	const char *fname;
	int fd;

	/* private */
	uint32_t target_pos;
	bool locked;

	uint8_t sha1[20];
	bool sha1_ready;
};

typedef enum {
	BSP_WHENCE_SET,
	BSP_WHENCE_FORWARD,
	BSP_WHENCE_REWIND,
	BSP_WHENCE_END,
} bsp_whence_t;

void bsp_io_init(struct bsp_io *, int fd, const char *fname);
off_t bsp_io_seek(struct bsp_ec *ec, struct bsp_io *io, off_t offset, bsp_whence_t whence);
off_t bsp_io_tell(struct bsp_ec *ec, struct bsp_io *io);
size_t bsp_io_pread(struct bsp_ec *ec, struct bsp_io *io, void *buffer, size_t length, off_t offset);
size_t bsp_io_read(struct bsp_ec *ec, struct bsp_io *io, void *buffer, size_t length);
void bsp_io_pwrite(struct bsp_ec *ec, struct bsp_io *io, const void *buffer, size_t length, off_t offset);
void bsp_io_write(struct bsp_ec *ec, struct bsp_io *io, const void *buffer, size_t length);
void bsp_io_pfill(struct bsp_ec *ec, struct bsp_io *io, uint32_t datum, uint_fast8_t width, size_t count, off_t offset);
void bsp_io_fill(struct bsp_ec *ec, struct bsp_io *io, uint32_t datum, uint_fast8_t width, size_t count);
off_t bsp_io_length(struct bsp_ec *ec, struct bsp_io *io);
void bsp_io_truncate(struct bsp_ec *ec, struct bsp_io *io, off_t length);
void bsp_io_lock(struct bsp_ec *ec, struct bsp_io *io, bool state);
const uint8_t *bsp_io_sha1(struct bsp_ec *ec, struct bsp_io *io);

#endif
