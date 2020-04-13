.PHONY: cppcheck

cppcheck:
	cppcheck -q --force --enable=style src/*.c src/lib/*.c src/lib/*.h
