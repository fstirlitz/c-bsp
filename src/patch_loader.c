static const char *patch_fname = NULL;

static int patch_fd = -1;
static enum { PATCH_MODE_MALLOC, PATCH_MODE_MMAP } patch_mode = PATCH_MODE_MALLOC;
static struct bsp_ps patch_space;

static void patch_load(void) {
	patch_mode = PATCH_MODE_MALLOC;

	if (patch_fname[0] == '-' && patch_fname[1] == '\0') {
		patch_fd = dup(0);
		if (patch_fd == -1) {
			fprintf(stderr, "%s: dup(0): %s\n", argv0, strerror(errno));
			exit(-1);
		}
	} else {
		patch_fd = open(patch_fname, O_RDONLY);
		if (patch_fd == -1) {
			fprintf(stderr, "%s: %s: open: %s\n", argv0, patch_fname, strerror(errno));
			exit(-1);
		}
	}

	off_t length = lseek(patch_fd, 0, SEEK_END);
	if (length == (off_t)-1) {
		if (errno != ESPIPE) {
			fprintf(stderr, "%s: %s: lseek: %s\n", argv0, patch_fname, strerror(errno));
			exit(-1);
		}

		length = 0;
		size_t capacity = 0x8000;
		void *buf = malloc(capacity);
		char *bufp = buf;

		for (;;) {
			if (length == capacity) {
				if (capacity == 0xffffffff)
					goto too_large_err;
				capacity *= 2;
				if (!capacity)
					capacity = 0xffffffff;
				else if ((capacity - 1) > 0xffffffff)
					goto too_large_err;
				buf = realloc(buf, capacity);
				if (buf == NULL) {
					perror("realloc(ps)");
					exit(-1);
				}
				bufp = buf + length;
			}

			ssize_t got = read(patch_fd, bufp, capacity - length);

			if (got == -1) {
				fprintf(stderr, "%s: %s: read: %s\n", argv0, patch_fname, strerror(errno));
				exit(-1);
			} else if (got == 0) {
				break;
			}

			if (length + got - 1 > 0xffffffff)
				goto too_large_err;

			length += got;
			bufp += got;
		}

		if (!length)
			goto empty_err;

		patch_space.space = buf;
		patch_space.limit = length - 1;

		return;
	}

	if (!length)
		goto empty_err;

	if (length - 1 > 0xffffffff)
		goto too_large_err;

	patch_space.limit = length - 1;
	patch_space.space = mmap(NULL, length, PROT_READ, MAP_PRIVATE, patch_fd, 0);
	if (patch_space.space != MAP_FAILED) {
		patch_mode = PATCH_MODE_MMAP;
		close(patch_fd);
		return;
	}

	patch_space.space = malloc(length);
	if (patch_space.space == NULL) {
		perror("malloc(ps)");
		exit(-1);
	}

	if (lseek(patch_fd, 0, SEEK_SET) == (off_t)-1) {
		fprintf(stderr, "%s: lseek(%s): %s\n", argv0, patch_fname, strerror(errno));
		exit(-1);
	}

	size_t left = length;
	char *bufp = (char *)patch_space.space;
	while (left) {
		ssize_t got = read(patch_fd, bufp, left);
		if (got == -1) {
			fprintf(stderr, "%s: read(%s): %s\n", argv0, patch_fname, strerror(errno));
			exit(-1);
		} else if (got == 0) {
			fprintf(stderr, "%s: read(%s): unexpected EOF\n", argv0, patch_fname);
			exit(-1);
		}
		left -= got;
	}

	close(patch_fd);
	return;

empty_err:
	patch_space.space = NULL;
	patch_space.limit = 0;
	return;

too_large_err:
	fprintf(stderr, "%s: %s: patch file is too large\n", argv0, patch_fname);
	exit(-1);

}

static void patch_unload(void) {
	switch (patch_mode) {

	case PATCH_MODE_MMAP:
		munmap((void *)patch_space.space, patch_space.limit + 1);
		return;

	case PATCH_MODE_MALLOC:
		free((void *)patch_space.space);
		return;

	}
}
