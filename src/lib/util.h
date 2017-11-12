#ifndef BSP_H_UTIL
#define BSP_H_UTIL

#define COUNT(array) (sizeof(array) / sizeof(array[0]))

inline static uint32_t min32(uint32_t a, uint32_t b) {
	return a < b ? a : b;
}

inline static uint8_t get_le8(const uint8_t *p) {
	return p[0];
}

inline static uint16_t get_le16(const uint8_t *p) {
	uint16_t result = 0;
	result |= (uint16_t)p[0];
	result |= (uint16_t)p[1] << 8;
	return result;
}

inline static uint32_t get_le32(const uint8_t *p) {
	uint32_t result = 0;
	result |= (uint32_t)p[0];
	result |= (uint32_t)p[1] << 8;
	result |= (uint32_t)p[2] << 16;
	result |= (uint32_t)p[3] << 24;
	return result;
}

inline static uint16_t get_be16(const uint8_t *p) {
	uint16_t result = 0;
	result |= (uint16_t)p[1];
	result |= (uint16_t)p[0] << 8;
	return result;
}

inline static uint32_t get_be24(const uint8_t *p) {
	uint32_t result = 0;
	result |= (uint32_t)p[2];
	result |= (uint32_t)p[1] << 8;
	result |= (uint32_t)p[0] << 16;
	return result;
}

inline static void put_le8(uint8_t *p, uint8_t value) {
	p[0] = value;
}

inline static void put_le16(uint8_t *p, uint16_t value) {
	p[0] = value;
	p[1] = value >> 8;
}

inline static void put_le32(uint8_t *p, uint32_t value) {
	p[0] = value;
	p[1] = value >> 8;
	p[2] = value >> 16;
	p[3] = value >> 24;
}

inline static uint32_t rol32(uint32_t v, uint8_t count) {
	count %= 32;
	if (count == 0)
		return v;
	return (v << count) | (v >> (32 - count));
}

#include <errno.h>
#include <stdlib.h>

inline static void *grow_alloc(void *p, size_t *cap, size_t grow_by, size_t elem_size) {
	size_t extra = *cap;
	size_t new_alloc;
	void *new_buffer;

	if (*cap + grow_by < *cap) {
		errno = ENOMEM;
		return NULL;
	}

	if ((*cap + grow_by) * elem_size < (*cap + grow_by)) {
		errno = ENOMEM;
		return NULL;
	}

	while (extra < grow_by) {
		if (*cap + extra < *cap) {
			extra = grow_by;
			break;
		} else {
			extra += *cap + extra;
		}
	}

	for (;;) {
		do {
			if (extra < grow_by)
				return NULL;
			new_alloc = *cap + extra;
			extra >>= 1;
		} while (new_alloc * elem_size < *cap * elem_size);

		new_buffer = realloc(p, new_alloc * elem_size);
		if (new_buffer != NULL) {
			*cap = new_alloc;
			return new_buffer;
		}
	}
}

#endif