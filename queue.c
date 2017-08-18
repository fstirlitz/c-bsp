#define Q_GLUE1(a, b) a ## b
#define Q_GLUE0(a, b) Q_GLUE1(a, b)
#define Q_FUNC(id) Q_GLUE0(Q_PREFIX, id)

struct Q_QTYPE {
	Q_TYPE *data;
	size_t cap, fin, off;
};

static bool Q_FUNC(empty)(struct Q_QTYPE *q) {
	return q->off == q->fin;
}

static void Q_FUNC(push)(struct Q_QTYPE *q, Q_TYPE value) {
	if (q->data == NULL || q->cap == q->fin) {
		if (q->off) {
			memmove(
				q->data, q->data + q->off,
				sizeof(*q->data) * (q->fin - q->off)
			);
			q->fin -= q->off;
			q->off = 0;
		} else {
			if (!q->cap)
				q->cap = 16;
			void *new_data = realloc(q->data, 2 * q->cap * sizeof(*q->data));
			if (new_data == NULL) {
				perror("realloc");
				exit(-1);
			}
			q->data = new_data;
			q->cap *= 2;
		}
	}
	q->data[q->fin++] = value;
}

inline static Q_TYPE Q_FUNC(shift)(struct Q_QTYPE *q) {
	return q->data[q->off++];
}

inline static void Q_FUNC(free)(struct Q_QTYPE *q) {
	free(q->data);
	q->data = NULL;
	q->cap = 0;
	q->fin = 0;
	q->off = 0;
}

#undef Q_GLUE1
#undef Q_GLUE0
#undef Q_FUNC

#undef Q_PREFIX
#undef Q_QTYPE
#undef Q_TYPE
