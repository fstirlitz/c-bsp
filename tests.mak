.PHONY: check coverage clean-gcno clean-coverage

PYTHON = python3

clean: clean-gcno clean-coverage

clean-gcno:
	rm -f *.gcno lib/*.gcno

clean-coverage:
	rm -f *.gcda lib/*.gcda
	rm -f *.gcov

check: bsp bspcomp/bspcomp
	rm -f *.gcda lib/*.gcda
	ret=0 ; for test in tests/*.test ; do \
		echo "--> $$test" ; \
		$(PYTHON) ./runtest "$$test" || ret=1 ; \
	done ; exit $$ret

# CFLAGS  += -ftest-coverage -fprofile-arcs
# LDFLAGS += -ftest-coverage -fprofile-arcs

coverage: check
	gcov -f -r *.gcda lib/*.gcda > Coverage.txt

bspcomp/bspcomp: bspcomp/bspcomp.o
