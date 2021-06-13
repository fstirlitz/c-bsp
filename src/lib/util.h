#ifndef BSP_H_UTIL
#define BSP_H_UTIL

#include <string.h>
#include <limits.h>

#define COUNT(array) (sizeof(array) / sizeof(array[0]))

inline static uint32_t min32(uint32_t a, uint32_t b) {
	return a < b ? a : b;
}

inline static uint8_t get_le8(const uint8_t *p) {
	return p[0];
}

#if CHAR_BIT != 8
#error Bit manipulation instructions that follow will perform incorrectly
#endif

inline static uint16_t get_le16(const uint8_t *p) {
	uint16_t result = 0;
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	memcpy(&result, p, sizeof(result));
#elif defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	memcpy(&result, p, sizeof(result));
	result = (result >> 8) | (result << 8);
#else
	result |= (uint16_t)p[0];
	result |= (uint16_t)p[1] << 8;
#endif
	return result;
}

inline static uint32_t get_le32(const uint8_t *p) {
	uint32_t result = 0;
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	memcpy(&result, p, sizeof(result));
#elif defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	memcpy(&result, p, sizeof(result));
	result = (result >> 24) | ((result >> 8) & 0x0000ff00) | ((result << 8) & 0x00ff0000) | (result << 24);
#else
	result |= (uint32_t)p[0];
	result |= (uint32_t)p[1] << 8;
	result |= (uint32_t)p[2] << 16;
	result |= (uint32_t)p[3] << 24;
#endif
	return result;
}

inline static uint16_t get_be16(const uint8_t *p) {
	uint16_t result = 0;
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	memcpy(&result, p, sizeof(result));
#elif defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	memcpy(&result, p, sizeof(result));
	result = (result >> 8) | (result << 8);
#else
	result |= (uint16_t)p[1];
	result |= (uint16_t)p[0] << 8;
#endif
	return result;
}

inline static uint32_t get_be24(const uint8_t *p) {
	uint32_t result = 0;
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	memcpy(&result, p, 3);
	result >>= 8;
#else
	result |= (uint32_t)p[2];
	result |= (uint32_t)p[1] << 8;
	result |= (uint32_t)p[0] << 16;
#endif
	return result;
}

inline static void put_le8(uint8_t *p, uint8_t value) {
	p[0] = value;
}

inline static void put_le16(uint8_t *p, uint16_t value) {
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	memcpy(p, &value, sizeof(value));
#elif defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	value = (value >> 8) | (value << 8);
	memcpy(p, &value, sizeof(value));
#else
	p[0] = value;
	p[1] = value >> 8;
#endif
}

inline static void put_le32(uint8_t *p, uint32_t value) {
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	memcpy(p, &value, sizeof(value));
#elif defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	value = (value >> 24) | ((value >> 8) & 0x0000ff00) | ((value << 8) & 0x00ff0000) | (value << 24);
	memcpy(p, &value, sizeof(value));
#else
	p[0] = value;
	p[1] = value >> 8;
	p[2] = value >> 16;
	p[3] = value >> 24;
#endif
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

#define UTF8_ERR_PAYLOAD_MASK      UINT32_C(0x00ffffff)
#define UTF8_ERR_TYPE_MASK         UINT32_C(0x8f000000)
#define UTF8_ERR_EOF              (int32_t)(UINT32_C(0x8b000000))
#define UTF8_ERR_SURROGATE(b)     (int32_t)(UINT32_C(0x8c000000) | (b))
#define UTF8_ERR_INVALID_UNIT(b)  (int32_t)(UINT32_C(0x8d000000) | (b))
#define UTF8_ERR_OVERLONG(b)      (int32_t)(UINT32_C(0x8e000000) | (b))
#define UTF8_ERR_OVERFLOW(b)      (int32_t)(UINT32_C(0x8f000000) | (b))

inline static int32_t utf8_decode_char(const char **data, size_t len) {
	const unsigned char *p = (const unsigned char *)*data;
	const unsigned char *fin = p + len;

	uint_fast8_t b = *p++, rem = 0;
	int32_t cpoint, min;

	/*  */ if ((b & 0x80) == 0x00) {
		cpoint = b;
		min = 0;
		rem = 0;
	} else if ((b & 0xe0) == 0xc0) {
		cpoint = b & 0x1f;
		min = 0x80;
		rem = 1;
	} else if ((b & 0xf0) == 0xe0) {
		cpoint = b & 0x0f;
		min = 0x800;
		rem = 2;
	} else if ((b & 0xf8) == 0xf0) {
		cpoint = b & 0x07;
		min = 0x10000;
		rem = 3;
	} else {
		return UTF8_ERR_INVALID_UNIT(*(p - 1));
	}

	while (rem--) {
		if (p >= fin)
			return UTF8_ERR_EOF;
		if ((*p & 0xc0) != 0x80)
			return UTF8_ERR_INVALID_UNIT(*p);
		cpoint <<= 6;
		cpoint |= *p++ & 0x3f;
	}

	if (cpoint < min)
		return UTF8_ERR_OVERLONG(cpoint);
	if (0xd800 <= cpoint && cpoint <= 0xdfff)
		return UTF8_ERR_SURROGATE(cpoint);
	if (cpoint > 0x10ffff)
		return UTF8_ERR_OVERFLOW(cpoint);

	*data = (const void *)p;
	return cpoint;
}

#endif
