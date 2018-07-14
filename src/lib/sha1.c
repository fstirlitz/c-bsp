#include "sha1.h"

#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>

#include "util.h"

void bsp_sha1_init(struct bsp_sha1_state *state) {
	state->length = 0;
	state->chunk_used = 0;

	state->h[0] = 0x67452301;
	state->h[1] = 0xefcdab89;
	state->h[2] = 0x98badcfe;
	state->h[3] = 0x10325476;
	state->h[4] = 0xc3d2e1f0;
}

static void bsp_sha1_hash_chunk(struct bsp_sha1_state *state, const uint8_t *chunk) {
	register uint32_t a, b, c, d, e, t, f, k;
	uint32_t w[80];

	a = state->h[0];
	b = state->h[1];
	c = state->h[2];
	d = state->h[3];
	e = state->h[4];

	for (int i = 0; i < 16; ++i) {
		w[i] =
			(((uint32_t)chunk[4 * i    ]) << 24) |
			(((uint32_t)chunk[4 * i + 1]) << 16) |
			(((uint32_t)chunk[4 * i + 2]) <<  8) |
			(((uint32_t)chunk[4 * i + 3])      ) ;
	}

	for (int i = 16; i < 80; ++i) {
		w[i] = rol32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
	}

	for (int i = 0; i < 80; ++i) {
		if (i < 20) {
			f = (b & c) | ((~b) & d);
			k = 0x5a827999;
		} else if (i < 40) {
			f = b ^ c ^ d;
			k = 0x6ed9eba1;
		} else if (i < 60) {
			f = (b & c) | (b & d) | (c & d);
			k = 0x8f1bbcdc;
		} else {
			f = b ^ c ^ d;
			k = 0xca62c1d6;
		}

		t = rol32(a, 5) + f + e + k + w[i];
		e = d;
		d = c;
		c = rol32(b, 30);
		b = a;
		a = t;
	}

	state->h[0] += a;
	state->h[1] += b;
	state->h[2] += c;
	state->h[3] += d;
	state->h[4] += e;
}

void bsp_sha1_update(struct bsp_sha1_state *state, const char *buffer, size_t size) {
	assert(state->chunk_used < sizeof(state->chunk));

	state->length += size;

	if (state->chunk_used) {
		size_t padsize = sizeof(state->chunk) - state->chunk_used;

		if (padsize > size)
			padsize = size;
		memcpy(state->chunk + state->chunk_used, buffer, padsize);
		state->chunk_used += padsize;
		if (state->chunk_used < sizeof(state->chunk))
			return;

		bsp_sha1_hash_chunk(state, state->chunk);

		size -= padsize;
		buffer += padsize;

		state->chunk_used = 0;
	}

	while (size >= sizeof(state->chunk)) {
		bsp_sha1_hash_chunk(state, (uint8_t *)buffer);
		buffer += sizeof(state->chunk);
		size -= sizeof(state->chunk);
	}

	if (size > 0) {
		memcpy(state->chunk + state->chunk_used, buffer, size);
		state->chunk_used += size;
	}
}

void bsp_sha1_finish(struct bsp_sha1_state *state, uint8_t *result) {
	assert(state->chunk_used < sizeof(state->chunk));

	memset(
		state->chunk + state->chunk_used, 0,
		sizeof(state->chunk) - state->chunk_used
	);
	state->chunk[state->chunk_used] = 0x80;
	if (state->chunk_used > (sizeof(state->chunk) - 8)) {
		bsp_sha1_hash_chunk(state, state->chunk);
		memset(state->chunk, 0, state->chunk_used + 1);
	}

	uint64_t len = state->length << 3;
	state->chunk[sizeof(state->chunk) - 8] = len >> 56;
	state->chunk[sizeof(state->chunk) - 7] = len >> 48;
	state->chunk[sizeof(state->chunk) - 6] = len >> 40;
	state->chunk[sizeof(state->chunk) - 5] = len >> 32;
	state->chunk[sizeof(state->chunk) - 4] = len >> 24;
	state->chunk[sizeof(state->chunk) - 3] = len >> 16;
	state->chunk[sizeof(state->chunk) - 2] = len >>  8;
	state->chunk[sizeof(state->chunk) - 1] = len      ;

	bsp_sha1_hash_chunk(state, state->chunk);

	for (int i = 0; i < 5; ++i) {
		result[4 * i    ] = state->h[i] >> 24;
		result[4 * i + 1] = state->h[i] >> 16;
		result[4 * i + 2] = state->h[i] >>  8;
		result[4 * i + 3] = state->h[i]      ;
	}
}
