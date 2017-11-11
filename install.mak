prefix     = /usr/local
libdir     = $(prefix)/lib
includedir = $(prefix)/include

.PHONY: install install-bin install-lib

install: install-bin

install-bin: all
	install -Dm0755 bsp     $(DESTDIR)$(prefix)/bin/bsp
	install -Dm0755 bspdis  $(DESTDIR)$(prefix)/bin/bspdis

install-lib: all
	# install -Dm0644 libbsp.a      $(DESTDIR)$(libdir)/libbsp.a
	# install -dm0755               $(DESTDIR)$(includedir)/libbsp
	# install -m0644 src/lib/*.h -t $(DESTDIR)$(includedir)/libbsp
