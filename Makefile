CC      = gcc
CCLD    = gcc
AR      = gcc-ar
CFLAGS  = -pipe -O3 -D_FORTIFY_SOURCE=2 \
	-Wall -Werror=implicit-function-declaration -Werror=format-security \
	-Werror=return-type -Werror=int-conversion -Werror=strict-prototypes \
	-Wstrict-aliasing=3
LDFLAGS = -pipe -O3 -fPIC

PACKAGES  =
INCLUDES  = # `pkg-config --cflags $(PACKAGES)`
LIBS      = # `pkg-config --libs $(PACKAGES)`

all: bsp bspdis lib/libbsp.a

.PHONY: all clean distclean

clean:
	rm -f *.o *.a lib/*.o lib/*.a bsp bspdis

distclean: clean
	rm -f deps.mak

bsp: bsp.o lib/libbsp.a

bspdis: bspdis.o lib/libbsp.a

lib/libbsp.a: lib/ec.o lib/ps.o lib/vm.o lib/sha1.o lib/ops.o lib/buf.o lib/stk.o lib/io.o lib/dis.o

%.a:
	$(AR) r '$@' $^

%.o: %.c
	$(CC) -c '$<' -o '$@' $(CFLAGS) $(INCLUDES)

bsp bspdis:
	$(CCLD) $^ -o '$@' $(LDFLAGS) $(LIBS)

include install.mak
include deps.mak
include tests.mak

deps.mak:
	( for f in *.c lib/*.c; do gcc -E -DMAKEDEPS=1 -I. -MM "$$f" -MT "$${f%.c}.o" $(CPPFLAGS) ; done ) > '$@'
