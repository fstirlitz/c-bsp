#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ctype.h>
#include <time.h>
#include <libgen.h>
#include <signal.h>
#include <locale.h>
#include <langinfo.h>
#include <iconv.h>

#include "lib/vm.h"
#include "lib/dis.h"
#include "lib/stk.h"
#include "lib/io.h"

#define INSN_LIMIT_DEFAULT 0x8000000
#define BRBK_LIMIT_DEFAULT 0x8000000
#define NEST_LIMIT_DEFAULT 128

static const char *argv0 = NULL;
static uint32_t insn_limit = INSN_LIMIT_DEFAULT, insn_count = 0;
static uint32_t brbk_limit = BRBK_LIMIT_DEFAULT, brbk_count = 0;
static uint32_t nest_limit = NEST_LIMIT_DEFAULT;

static void show_usage(void) {
	fprintf(stderr,
		"usage: %s [options] PATCH_SCRIPT SOURCE_FILE [TARGET_FILE]\n"
		"Interpreter for Binary Scripted Patch files.\n"
		"\n"
		"arguments:\n"
		"  PATCH_SCRIPT     the BSP file containing the patch\n"
		"  SOURCE_FILE      the file to be patched\n"
		"  TARGET_FILE      the file into which the patching result should be written\n"
		"                   (default: same as SOURCE_FILE)\n"
		"\n"
		"options:\n"
		"  -d               debug mode: show additional information\n"
		"  -t               trace executed instructions\n"
		"  -tt              trace executed instructions and their operands\n"
		"  -k               keep temporary 'scratch' file even if patching fails\n"
		"  -I INSN_LIMIT    set limit of executed instructions\n"
		"                   (default: %u; -1 to disable)\n"
		"  -N NEST_LIMIT    set limit of nested BSP patches\n"
		"                   (default: %u; -1 to disable)\n"
		"  -J BRBK_LIMIT    set limit of backward jumps\n"
		"                   (default: %u; -1 to disable)\n"
		"\n", argv0, INSN_LIMIT_DEFAULT, NEST_LIMIT_DEFAULT, BRBK_LIMIT_DEFAULT
	);
	exit(-1);
}

#define DBG_TRACE           0x0001 // show opcode before executing
#define DBG_TRACE_OPERANDS  0x0002 // show operands as well
#define DBG_VERBOSE         0x0004 // show miscellaneous info

static unsigned int debug_flags = 0;

#include "hexdump.c"

static void dump_opcode(struct bsp_vm *vm, struct bsp_opcode *opc) {
	const char *mnemonic = bsp_op_get_mnemonic(opc);
	uint32_t pc = vm->pc;

	size_t op_size = vm->pc_next - vm->pc;
	const uint8_t *opc_bytes = bsp_ps_getp(NULL, vm->ps, pc, op_size);

	fprintf(stderr, "[%3u/%06x] %08x  ", vm->nest_level, insn_count, pc);
	fhexdump(stderr, opc_bytes, op_size, 12);
	fprintf(stderr, "%-18s", mnemonic);

	bool comma = false;

	for (int i = 0; i < BSP_OPNUM; ++i) {
		if (opc->optyp[i] == BSP_OPD_NONE)
			continue;

		if (comma)
			fprintf(stderr, ", ");
		else
			comma = true;

		switch (opc->optyp[i]) {
		case BSP_OPD_NONE:
			abort(); /* handled above */
		case BSP_OPD_IMM8:
			fprintf(stderr, "0x%02x", opc->opval[i]);
			break;
		case BSP_OPD_IMM16:
			fprintf(stderr, "0x%04x", opc->opval[i]);
			break;
		case BSP_OPD_IMM32:
			fprintf(stderr, "0x%08x", opc->opval[i]);
			break;
		case BSP_OPD_RREG:
		case BSP_OPD_MREG:
		case BSP_OPD_WREG:
			fprintf(stderr, "#%u", opc->opval[i]);
			break;
		}
	}

	fprintf(stderr, "\n");
}

static void dump_operands(struct bsp_vm *vm, struct bsp_opcode *opc, bool after) {
	bsp_opsems_t sems = bsp_op_get_sems(opc);
	bsp_opflags_t flags = bsp_op_get_flags(opc);
	struct bsp_ec ec;

#define INDENT_NEST \
	" " "   " " " "      " " "
#define INDENT_OPC \
	"                        "
#define INDENT_OFFS \
	"        "

#define INDENT \
	INDENT_NEST " " INDENT_OFFS "  " INDENT_OPC

	if ((flags & BSP_OPFLAG_POP) && !after) {
		if (!bsp_stk_getsize(vm)) {
			fprintf(stderr, INDENT "stk[0] = (empty)\n");
		} else {
			fprintf(stderr, INDENT "stk[0] = 0x%08x\n", *bsp_stk_getslot(vm, 0));
		}
	}

	if ((flags & BSP_OPFLAG_WRPOS) || (!after && (flags & BSP_OPFLAG_RDPOS))) {
		do {
			if (bsp_try(&ec)) {
				bsp_ec_clear(&ec);
				break;
			}

			fprintf(stderr, INDENT "pos  = 0x%08x\n", (uint32_t) bsp_io_tell(&ec, vm->io));
		} while (0);
	}

	for (int i = 0; i < BSP_OPNUM; ++i) {
		switch (opc->optyp[i]) {
		case BSP_OPD_NONE:
		case BSP_OPD_IMM8:
		case BSP_OPD_IMM16:
		case BSP_OPD_IMM32:
			continue;
		case BSP_OPD_RREG:
			if (after)
				continue;
			break;
		case BSP_OPD_WREG:
			if (!after)
				continue;
			break;
		case BSP_OPD_MREG:
			break;
		}

		/* don't display the same register more than once */
		int j;
		for (j = 0; j < i; ++j) {
			switch (opc->optyp[j]) {
			case BSP_OPD_NONE:
			case BSP_OPD_IMM8:
			case BSP_OPD_IMM16:
			case BSP_OPD_IMM32:
				continue;
			case BSP_OPD_RREG:
				if (after)
					continue;
				break;
			case BSP_OPD_WREG:
				if (!after)
					continue;
				break;
			case BSP_OPD_MREG:
				break;
			}

			if (opc->opval[i] == opc->opval[j])
				break;
		}

		if (j != i)
			continue;

		fprintf(stderr, INDENT "#%-3u = 0x%08x\n", opc->opval[i], vm->regs[opc->opval[i]]);
	}

	for (int i = 0; i < BSP_OPNUM; ++i) {
		uint32_t value;

		switch (opc->optyp[i]) {
		case BSP_OPD_NONE:
			continue;
		case BSP_OPD_IMM8:
		case BSP_OPD_IMM16:
		case BSP_OPD_IMM32:
			if (after)
				continue;
			value = opc->opval[i];
			break;
		case BSP_OPD_WREG:
			if (!after)
				continue;
			/* fallthrough */
		case BSP_OPD_RREG:
		case BSP_OPD_MREG:
			value = vm->regs[opc->opval[i]];
			break;
		default:
			abort();
		}

		switch (BSP_OPSEM_AT(sems, i)) {
		case BSP_OPSEM_STACK:
			break;

		case BSP_OPSEM_STACKR:
		case BSP_OPSEM_STACKW: {
			if (after == (BSP_OPSEM_AT(sems, i) == BSP_OPSEM_STACKR))
				break;

			if (value & 0x80000000) {
				fprintf(stderr, INDENT "stk[-%u] = ", -value);
			} else {
				fprintf(stderr, INDENT "stk[%u] = ", value);
			}

			uint32_t *slot = bsp_stk_getslot(vm, value);
			if (slot != NULL)
				fprintf(stderr, "0x%08x\n", *slot);
			else
				fprintf(stderr, "(overflow)\n");
			break;
		}

		case BSP_OPSEM_PTR_STR:
			if (after)
				break;
			if (bsp_try(&ec)) {
				bsp_ec_clear(&ec);
				break;
			}
			size_t len;
			const char *s = bsp_ps_getsz(&ec, vm->ps, value, &len);

			fprintf(stderr, INDENT_NEST " " "%08x" "  " INDENT_OPC, value);
			fprintf(stderr, "%-18s", "string");
			fprintf(stderr, "\"");
			for (size_t i = 0; i < len; ++i) {
				fprintf(stderr, "%c%s", s[i], s[i] == '"' ? "\"" : "");
			}
			fprintf(stderr, "\"");
			fprintf(stderr, "\n");
			break;

		case BSP_OPSEM_PTR_SHA1: {
			if (after)
				break;
			if (bsp_try(&ec)) {
				bsp_ec_clear(&ec);
				break;
			}

			const uint8_t *hash = bsp_ps_getp(&ec, vm->ps, value, 20);
			fprintf(stderr, INDENT_NEST " " "%08x" "  " INDENT_OPC, value);
			fprintf(stderr, "%-18s", "hexdata");
			for (int i = 0; i < 20; ++i)
				fprintf(stderr, "%02x", hash[i]);
			fprintf(stderr, "\n");
			break;
		}

		}
	}
}

static volatile sig_atomic_t abort_flag = 0;

static void handle_sigint(int signum) {
	abort_flag = 1;
}

static void exec_cb(struct bsp_ec *ec, struct bsp_vm *vm, struct bsp_opcode *opc) {
	if (abort_flag)
		bsp_die(ec, "interrupt signal received");
	if (++insn_count > insn_limit) {
		--insn_count;
		bsp_die(ec, "limit of executed instructions (%u) reached", insn_limit);
	}

	if (debug_flags & DBG_TRACE) {
		if (debug_flags & DBG_TRACE_OPERANDS)
			dump_operands(vm, opc, false);
		dump_opcode(vm, opc);
	}
}

static void postexec_cb(struct bsp_ec *ec, struct bsp_vm *vm, struct bsp_opcode *opc) {
	if (debug_flags & DBG_TRACE) {
		if (debug_flags & DBG_TRACE_OPERANDS) {
			dump_operands(vm, opc, true);
			fprintf(stderr, INDENT "------\n");
		}
	}

	if (vm->pc_next <= vm->pc) {
		if (++brbk_count > brbk_limit)
			bsp_die(ec, "backward jump limit (%u) reached", brbk_limit);
	}
}

static void fetch_cb(struct bsp_ec *ec, struct bsp_vm *vm) {
	if (vm->nest_level > nest_limit)
		bsp_die(ec, "limit of nesting BSP patches (%u) exceeded", nest_limit);
}

static iconv_t iconv_cd = (iconv_t)-1;

static void print_cb(struct bsp_ec *ec, struct bsp_vm *vm, const char *msg, size_t length) {
	for (const char *cp = msg; cp < msg + length; ++cp) {
		uint8_t ch = *cp;
		// specifically allow whitespace
		if (ch == '\r' || ch == '\n' || ch == '\t')
			continue;
		// disallow other control characters (ANSI bombs, anyone?)
		if (ch < 0x20)
			bsp_die(ec, "attempt to print out an illegal character 0x%02x", ch);
	}

	if (iconv_cd == (iconv_t)-1) {
		fwrite(msg, length, 1, stdout);
	} else {
		const char *msgp = msg;
		char buffer[1024], *bufp = buffer;
		size_t bufl = sizeof(buffer);

		while (length) {
			bufp = buffer; bufl = sizeof(buffer);
			iconv(iconv_cd, (char **)&msgp, &length, &bufp, &bufl);

			if (bufl == sizeof(buffer)) {
				*bufp++ = '?';

				uint8_t ch = *msgp;
				size_t s = 1;
				if ((ch & 0xe0) == 0xc0)
					s = 2;
				else if ((ch & 0xf0) == 0xe0)
					s = 3;
				else if ((ch & 0xf8) == 0xf0)
					s = 4;
				msgp += s; length -= s;
			}

			fwrite(buffer, bufp - buffer, 1, stdout);
		}

		bufp = buffer; bufl = sizeof(buffer);
		iconv(iconv_cd, NULL, 0, &bufp, &bufl);
		fwrite(buffer, bufp - buffer, 1, stdout);
	}

	fputs("\n", stdout);
}

static uint_fast32_t menu_cb(struct bsp_ec *ec, struct bsp_vm *vm,
	uint_fast32_t count, const char *items[], const size_t lens[])
{
	for (uint_fast32_t i = 0; i < count; ++i) {
		printf("%lu. %.*s\n", (unsigned long)i, (int)lens[i], items[i]);
	}
	fflush(stdout);

	for (;;) {
		printf("[0..%lu, q to abort]? ", (unsigned long)count - 1);
		fflush(stdout);

		int c = fgetc(stdin);

		while (isspace(c))
			c = fgetc(stdin);

		if (c == EOF || c == 'q') {
			if (c == EOF)
				printf("\n");
			bsp_return(ec, BSP_RET_USER_ABORT);
		}

		if (isdigit(c)) {
			uint_fast32_t sel = c - '0';
			for (;;) {
				c = fgetc(stdin);
				if (isdigit(c)) {
					sel *= 10;
					sel += c - '0';
					continue;
				} else if (c == '\n' || c == EOF) {
					if (sel < count)
						return sel;
				}
				break;
			}
		}

		while (!iscntrl(c))
			c = fgetc(stdin);
	}
}

#include "patch_loader.c"

static void fatal_cb(struct bsp_vm *vm, bsp_ret_t ret, struct bsp_ec *ec) {
	vm->cb->fatal = NULL;

	switch (ret) {

	default:
		fprintf(stderr, "%s: unknown return code %u\n", argv0, ret);
		abort();

	case BSP_RET_USER_ABORT:
		fprintf(stderr, "%s: aborted by user\n", argv0);
		break;

	case BSP_RET_FATAL:
		fprintf(stderr, "%s: fatal error: %s\n", argv0, ec->fatal_msg);
		break;

	}

	fprintf(stderr, "  traceback after %u ops executed:\n", insn_count);
	while (vm != NULL) {
		fprintf(stderr, "   %4u. pc=0x%08x  stk#=%zu  ",
			vm->nest_level, vm->pc,
			bsp_stk_getsize(vm)
		);

		if (vm->parent) {
			const struct bsp_ps *parent_ps = vm->parent->ps;
			const struct bsp_ps *ps = vm->ps;

			uint32_t off = ps->space - parent_ps->space;

			fprintf(stderr, "(+0x%08x, limit 0x%08x)", off, ps->limit);
		} else {
			fprintf(stderr, "[%s]", patch_fname);
		}
		fprintf(stderr, "\n");

		vm = vm->parent;
	}
}


static const char *source_fname = NULL;
static const char *target_fname = NULL;
static bool scratch_keep = false;

static unsigned long parse_cmdline_num(const char *arg) {
	char *errp;
	unsigned long val = strtoul(arg, &errp, 0);

	if (*errp) {
		fprintf(stderr, "%s: invalid number: '%s'\n", argv0, arg);
		exit(-1);
	}

	return val;
}

static void parse_cmdline(char *argv[]) {
	for (size_t i = 1; argv[i]; i++) {
		const char *arg = argv[i];
		if (arg == NULL)
			break;

		if (arg[0] == '-') {
			if (arg[1] == '\0') {
				fprintf(stderr, "%s: cannot use standard streams for I/O\n", argv0);
				exit(-1);
			}

			const char *optarg = NULL;

#define TAKE_OPTARG() (arg[1] \
	? (optarg = arg, arg += strlen(arg + 1), ++optarg) \
	: (optarg = argv[++i]))

			for (++arg; *arg; ++arg) {
				switch (*arg) {

				case 'd':
					debug_flags |= DBG_VERBOSE;
					break;

				case 'k':
					scratch_keep = true;
					break;

				case 't':
					if (debug_flags & DBG_TRACE)
						debug_flags |= DBG_TRACE_OPERANDS;
					debug_flags |= DBG_TRACE;
					break;

				case 'I':
					insn_limit = parse_cmdline_num(TAKE_OPTARG());
					break;

				case 'N':
					nest_limit = parse_cmdline_num(TAKE_OPTARG());
					break;

				case 'J':
					brbk_limit = parse_cmdline_num(TAKE_OPTARG());
					break;

				default:
					show_usage();

				}
			}

#undef TAKE_OPTARG

		} else {
			if (patch_fname == NULL)
				patch_fname = arg;
			else if (source_fname == NULL)
				source_fname = arg;
			else if (target_fname == NULL)
				target_fname = arg;
			else
				show_usage();
		}
	}

	if (patch_fname == NULL)
		show_usage();
	if (source_fname == NULL)
		show_usage();
	if (target_fname == NULL)
		target_fname = source_fname;
}

// scratch file

static enum { SCRATCH_MODE_COPY, SCRATCH_MODE_TMPFILE } scratch_mode = SCRATCH_MODE_COPY;
static int scratch_fd = -1;
static char *scratch_fname = NULL;

#include "lib/asprintf.c"

static void scratch_open(int mode) {
#if defined(__linux__) && defined(O_TMPFILE)
	if (!scratch_keep) {
		scratch_fname = strdup(target_fname);
		scratch_fd = open(dirname(scratch_fname), O_TMPFILE | O_RDWR, mode);
		if (scratch_fd != -1) {
			scratch_mode = SCRATCH_MODE_TMPFILE;
			free(scratch_fname);
			scratch_fname = NULL;
			if (debug_flags & DBG_VERBOSE)
				fprintf(stderr, "%s: ephemeral scratch file created\n", argv0);
			return;
		}

		if (errno != EISDIR && errno != ENOTSUP) {
			fprintf(stderr, "%s: open(%s, O_TMPFILE): %s\n", argv0, scratch_fname, strerror(errno));
			exit(-1);
		}

		free(scratch_fname);
	}
#endif

	if (asprintf(&scratch_fname, "%s.%u.XXXXXXXXX", target_fname, getpid()) == -1) {
		fprintf(stderr, "%s: asprintf: %s\n", argv0, strerror(errno));
		exit(-1);
	}

	scratch_fd = mkstemp(scratch_fname);
	if (scratch_fd == -1) {
		fprintf(stderr, "%s: mkstemp: %s\n", argv0, strerror(errno));
		exit(-1);
	}
	fchmod(scratch_fd, mode);
}

static void scratch_clone(void) {
	int fd_orig = open(source_fname, O_RDONLY);
	if (fd_orig == -1) {
		fprintf(stderr, "%s: open(%s): %s\n", argv0, source_fname, strerror(errno));
		exit(-1);
	}

	scratch_open(0660);

	// XXX: copy xattrs, acls

	uint_fast32_t target_length = 0;
	for (;;) {
		char buffer[2048];
		ssize_t got = read(fd_orig, buffer, sizeof(buffer));
		if (got == 0) {
			break;
		}

		if (got == -1) {
			fprintf(stderr, "%s: read(%s): %s\n", argv0, source_fname, strerror(errno));
			exit(-1);
		}

		target_length += got;

		char *bufp = buffer;
		while (got > 0) {
			ssize_t wrote = write(scratch_fd, bufp, got);

			if (wrote == -1) {
				fprintf(stderr, "%s: write(%s): %s\n", argv0, scratch_fname, strerror(errno));
				exit(-1);
			}

			got -= wrote;
			bufp += wrote;
		}
	}

	close(fd_orig);
}

static void scratch_cancel(void) {
	switch (scratch_mode) {

	case SCRATCH_MODE_COPY:
		close(scratch_fd);
		if (scratch_keep) {
			if (debug_flags & DBG_VERBOSE)
				fprintf(stderr, "%s: keeping scratch file '%s'\n", argv0, scratch_fname);
			return;
		}
		if (debug_flags & DBG_VERBOSE)
			fprintf(stderr, "%s: deleting scratch file '%s'\n", argv0, scratch_fname);
		if (unlink(scratch_fname) == -1) {
			fprintf(stderr, "%s: unlink(%s): %s\n", argv0, scratch_fname, strerror(errno));
			/* do not exit(-1); we are already failing */
		}
		return;

	case SCRATCH_MODE_TMPFILE:
		close(scratch_fd);
		return;

	}
}

static void scratch_commit(void) {
	if (fdatasync(scratch_fd) == -1) {
		fprintf(stderr, "%s: fdatasync(%s): %s\n", argv0, scratch_fname ? scratch_fname : target_fname, strerror(errno));
		scratch_cancel();
		exit(-1);
	}

	switch (scratch_mode) {

	case SCRATCH_MODE_COPY:
		close(scratch_fd);
		if (rename(scratch_fname, target_fname) == -1) {
			fprintf(stderr, "%s: rename(%s -> %s): %s\n", argv0, scratch_fname, target_fname, strerror(errno));
			exit(-1);
		}
		return;

	case SCRATCH_MODE_TMPFILE: {
		if (unlink(target_fname) == -1) {
			if (errno != ENOENT) {
				fprintf(stderr, "%s: unlink(%s): %s\n", argv0, target_fname, strerror(errno));
				exit(-1);
			}
		}

		char procfd[sizeof("/proc/self/fd/4294967295")];
		snprintf(procfd, sizeof(procfd), "/proc/self/fd/%u", scratch_fd);

		if (linkat(AT_FDCWD, procfd, AT_FDCWD, target_fname, AT_SYMLINK_FOLLOW) == -1) {
			fprintf(stderr, "%s: linkat(#%u <- %s): %s\n", argv0, scratch_fd, target_fname, strerror(errno));
			exit(-1);
		}

		close(scratch_fd);
	}

	}
}

int main(int argc, char *argv[]) {
	setlocale(LC_ALL, "");
	const char *codeset = nl_langinfo(CODESET);

	if (strcasecmp(codeset, "UTF-8") != 0) {
#if defined(__GLIBC__)
		char tr_codeset[strlen(codeset) + sizeof("//TRANSLIT")];
		snprintf(tr_codeset, sizeof(tr_codeset), "%s//TRANSLIT", codeset);
		iconv_cd = iconv_open(tr_codeset, "utf-8");

		if (iconv_cd == (iconv_t)-1)
#endif
		iconv_cd = iconv_open(codeset, "utf-8");
	}

	argv0 = argv[0];
	parse_cmdline(argv);

	int ret = -1;

	struct bsp_ec ec;
	bsp_ret_t bret;

	if ((bret = bsp_try(&ec))) {
		fprintf(stderr, "%s: failed to init VM: %s\n",
			argv0,
			ec.fatal_msg
		);
		exit(-1);
	}

	patch_load();

	struct bsp_io io;
	scratch_clone();
	bsp_io_init(&io, scratch_fd, scratch_fname);

	struct bsp_vm vm;
	bsp_init(&ec, &vm, &patch_space, &io);

	struct bsp_cb callbacks = {
		.print = print_cb,
		.menu = menu_cb,
		.fetch = fetch_cb,
		.exec = exec_cb,
		.postexec = postexec_cb,
		.fatal = fatal_cb,
	};

	vm.cb = &callbacks;

	struct sigaction sigint_action;
	sigint_action.sa_flags = 0;
	sigint_action.sa_handler = handle_sigint;
	sigemptyset(&sigint_action.sa_mask);
	sigaction(SIGINT, &sigint_action, NULL);

	if ((bret = bsp_try(&ec))) {
		goto fail;
	}

	uint32_t exit_code = bsp_run(&ec, &vm);

	ret = exit_code > 254 ? 254 : exit_code;

	if (exit_code == 0) {
		if (debug_flags & DBG_VERBOSE) {
			fprintf(stderr, "%s: %s[+0x%x]: patching successful, exit code %u\n",
				argv0, patch_fname, vm.pc,
				exit_code
			);
		}

		scratch_commit();
	} else {
		if (debug_flags & DBG_VERBOSE) {
			fprintf(stderr, "%s: %s[+0x%x]: patching failed, exit code %u\n",
				argv0, patch_fname, vm.pc,
				exit_code
			);
		}

	fail:
		scratch_cancel();
	}

	if (debug_flags & DBG_VERBOSE) {
		fprintf(stderr, "%s: %s: %u instructions executed\n",
			argv0, patch_fname,
			insn_count
		);

		fprintf(stderr, "%s: %s: %u backward jumps\n",
			argv0, patch_fname,
			brbk_count
		);
	}

	bsp_fini(&vm);
	patch_unload();

	return ret;
}
