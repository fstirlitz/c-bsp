#include "io.h"

#include "sha1.h"
#include "util.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

inline static noreturn void bsp_die_perror(struct bsp_ec *ec, struct bsp_io *io, const char *func) {
	bsp_die(ec, "%s: %s: %s [%d]", io->fname, func, strerror(errno), errno);
}

void bsp_io_init(struct bsp_io *io, int fd, const char *fname) {
	io->fd = fd;
	io->fname = fname;

	io->locked = false;
	io->target_pos = 0;
	io->sha1_ready = false;
}

size_t bsp_io_pread(struct bsp_ec *ec, struct bsp_io *io, void *buffer, size_t length, off_t offset) {
	if (!length)
		return 0;

	ssize_t got = pread(io->fd, buffer, length, offset);
	if (got == -1)
		bsp_die_perror(ec, io, "pread");

	return got;
}

size_t bsp_io_read(struct bsp_ec *ec, struct bsp_io *io, void *buffer, size_t length) {
	size_t got = bsp_io_pread(ec, io, buffer, length, io->target_pos);
	bsp_io_seek(ec, io, got, BSP_WHENCE_FORWARD);
	return got;
}

void bsp_io_pfill(struct bsp_ec *ec, struct bsp_io *io, uint32_t datum, uint_fast8_t width, size_t count, off_t offset) {
	if (!count || !width)
		return;

	io->sha1_ready = false;

	char buffer[1024];
	for (size_t i = 0; i < sizeof(buffer); i += width) {
		for (size_t j = 0; j < width; ++j) {
			buffer[i + j] = datum >> (j << 3);
		}
	}

	while (count > 0) {
		size_t n = min32(count, sizeof(buffer) / width);
		ssize_t wrote = pwrite(io->fd, buffer, n * width, offset);
		if (wrote == -1)
			bsp_die_perror(ec, io, "pwrite");
		count  -=  wrote / width;
		offset +=  wrote - (wrote % width);
	}
}

void bsp_io_fill(struct bsp_ec *ec, struct bsp_io *io, uint32_t datum, uint_fast8_t width, size_t count) {
	bsp_io_pfill(ec, io, datum, width, count, io->target_pos);
	bsp_io_seek(ec, io, width * count, BSP_WHENCE_FORWARD);
}

void bsp_io_pwrite(struct bsp_ec *ec, struct bsp_io *io, const void *buffer, size_t length, off_t offset) {
	if (!length)
		return;

	io->sha1_ready = false;

	const char *bufp = buffer;
	while (length > 0) {
		ssize_t wrote = pwrite(io->fd, bufp, length, offset);
		if (wrote == -1)
			bsp_die_perror(ec, io, "pwrite");
		length -= wrote;
		offset += wrote;
		bufp   += wrote;
	}
}

void bsp_io_write(struct bsp_ec *ec, struct bsp_io *io, const void *buffer, size_t length) {
	bsp_io_pwrite(ec, io, buffer, length, io->target_pos);
	bsp_io_seek(ec, io, length, BSP_WHENCE_FORWARD);
}

off_t bsp_io_tell(struct bsp_ec *ec, struct bsp_io *io) {
	return io->target_pos;
}

off_t bsp_io_seek(struct bsp_ec *ec, struct bsp_io *io, off_t offset, bsp_whence_t whence) {
	if (io->locked)
		return io->target_pos;

	off_t old = io->target_pos;

	switch (whence) {
	case BSP_WHENCE_SET:
		if (offset < 0)
			bsp_die(ec, "attempt to seek to a negative offset");
		if (offset > 0xffffffff)
			bsp_die(ec, "file offset overflow");
		io->target_pos  = offset;
		break;
	case BSP_WHENCE_FORWARD:
		if ((uint32_t)(io->target_pos + offset) < io->target_pos)
			bsp_die(ec, "file offset overflow");
		io->target_pos += offset;
		break;
	case BSP_WHENCE_REWIND:
		if (io->target_pos < offset)
			bsp_die(ec, "attempt to rewind before the beginning of the file");
		io->target_pos -= offset;
		break;
	case BSP_WHENCE_END:
		if (offset > bsp_io_length(ec, io))
			bsp_die(ec, "attempt to rewind before the beginning of the file");
		io->target_pos = bsp_io_length(ec, io) - offset;
		break;
	}

	return old;
}

off_t bsp_io_length(struct bsp_ec *ec, struct bsp_io *io) {
	off_t ret = lseek(io->fd, 0, SEEK_END);
	if (ret == -1)
		bsp_die_perror(ec, io, "lseek");
	return ret;
}

void bsp_io_truncate(struct bsp_ec *ec, struct bsp_io *io, off_t length) {
	int ret = ftruncate(io->fd, length);
	if (ret == -1)
		bsp_die_perror(ec, io, "ftruncate");
}

void bsp_io_lock(struct bsp_ec *ec, struct bsp_io *io, bool state) {
	io->locked = state;
}

const uint8_t *bsp_io_sha1(struct bsp_ec *ec, struct bsp_io *io) {
	if (io->sha1_ready)
		return io->sha1;

	struct bsp_sha1_state state;

	bsp_sha1_init(&state);
	off_t offset = 0;

	for (;;) {
		char buffer[2048];
		size_t got = bsp_io_pread(ec, io, buffer, sizeof(buffer), offset);
		if (got == 0) {
			break;
		}

		bsp_sha1_update(&state, buffer, got);
		offset += got;
	}

	bsp_sha1_finish(&state, io->sha1);
	io->sha1_ready = true;

	return io->sha1;
}
