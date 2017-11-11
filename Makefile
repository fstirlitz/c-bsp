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

all: bsp bspdis libbsp.a

.PHONY: all clean distclean

clean:
	rm -f *.a src/*.o src/lib/*.o lib/*.a bsp bspdis

distclean: clean
	rm -f deps.mak

bsp: src/bsp.o libbsp.a

bspdis: src/bspdis.o libbsp.a

libbsp.a: \
	src/lib/ec.o \
	src/lib/ps.o \
	src/lib/vm.o \
	src/lib/sha1.o \
	src/lib/ops.o \
	src/lib/buf.o \
	src/lib/stk.o \
	src/lib/io.o \
	src/lib/dis.o

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
	( for f in src/*.c src/lib/*.c; do gcc -E -DMAKEDEPS=1 -I. -MM "$$f" -MT "$${f%.c}.o" $(CPPFLAGS) ; done ) > '$@'
