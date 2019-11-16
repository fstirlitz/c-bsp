#if defined(__GLIBC__) || defined(__BIONIC__)
#	define HAVE_ASPRINTF 1
#endif

#if !defined(HAVE_ASPRINTF)
static int vasprintf(char **strp, const char *fmt, va_list ap) {
	int sz;
	va_list aq;

	va_copy(aq, ap);
	sz = vsnprintf(NULL, 0, fmt, aq);
	va_end(aq);

	if (sz == -1)
		return -1;
	*strp = malloc(sz + 1);
	if (*strp == NULL)
		return -1;
	(*strp)[sz] = '\0';
	return vsnprintf(*strp, sz, fmt, ap);
}

static int asprintf(char **strp, const char *fmt, ...) {
	int ret;
	va_list ap;

	va_start(ap, fmt);
	ret = vasprintf(strp, fmt, ap);
	va_end(ap);
	return ret;
}
#endif
