# C-BSP

This is a C11 implementation of the [Binary Scripted Patch specification,
version as of September 2017][spec]. It was developed on Linux/glibc,
but should be easy to port to other Unix-like systems.

Contains:
- `bsp`: an interpreter, operated from the command line.
- `bspdis`: a disassembler with rudimentary control flow awareness.

Notes on implementation:
- The file buffer is not kept in memory, but in a temporary file. This
  temporary file is deleted upon patching failure (this may be overridden
  with the `-k` option), and otherwise moved to the target file name. The
  patched file is not operated on directly, to ensure that patching is atomic.
- To prevent infinite loops and runaway nesting of embedded patches (invoked
  via the `bsppatch` instruction), limits on the number of nested patches
  and executed instructions have been established. By default, there is a
  maximum of 128 nesting levels and a maxmum of 8 Mi (8,388,608) executed
  instructions across all nesting levels; those limits can be adjusted via
  the command-line options `-N` and `-I`, respectively.
- The stack and the output buffer are implemented as dynamic arrays;
  no limits have been imposed on their size at the moment (this may change).
  Failure to allocate memory for either generates a fatal error. The initial
  allocation ensures there is space for 128 bytes in the buffer and 32 words
  on the stack.
- Nested patch execution has been implemented via the C call stack. Thus,
  running an erratic patch script with a high nesting limit may overflow
  the stack and generate a segmentation fault. The default limit is not
  expected to cause issues on platforms without tight memory constraints;
  128 levels of nesting will consume about 192 KiB of stack memory (on x86).
  Please note that the output buffer and the patch script's own stack are
  allocated on the heap, and may exhaust memory independently from stack
  allocations.
- The exit code from the (top-level) script becomes the interpreter's own
  exit code, unless it is larger than 254, in which case the exit code is
  clamped to that value. An interpreter exit code of 255 is reserved for
  fatal errors and other errors not returned by the script itself. This is
  because POSIX prescribes that only the lower 8 bits of the exit code of a
  process are significant. The full exit status can be obtained by using the
  `-d` option.
- Attempting to print out or put into a buffer an invalid UTF-8 string
  triggers a fatal error, just like in the reference implementation.
  However, attempting to print a character which cannot be represented in
  the system encoding will instead lossily convert it. Both behaviours may
  change in a future version.

## TODO

- An interactive debugger.
- A graphical interface.
- A test suite.
- Rewrite It In Rust™.
- Batch/non-interactive mode?
- Interactive disassembler?
- Symbolic control flow analysis?

[spec]: https://github.com/aaaaaa123456789/bsp/blob/c2afec8713dd13f95f74c8c685008e455d2f2965/specification.md
