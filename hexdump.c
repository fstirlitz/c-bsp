static void fhexdump(FILE *f, const uint8_t *data, size_t length, size_t pad) {
    size_t i = 0;
    for (; i < length; ++i)
        fprintf(f, "%02x", data[i]);
    while (i++ < pad)
        fprintf(f, "  ");
}
