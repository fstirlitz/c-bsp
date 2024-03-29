#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <limits.h>
#include <ctype.h>
#include <stdbool.h>

#include "lib/ps.h"
#include "lib/dis.h"
#include "lib/util.h"

static const char *argv0 = NULL;

static void show_usage(void) {
	fprintf(stderr,
		"usage: %s [-n] [-o OUTPUT_FILE] PATCH_SCRIPT [HINT [...]]\n"
		"Disassembler for Binary Scripted Patch files.\n"
		"\n"
		"arguments:\n"
		"  PATCH_SCRIPT     the BSP file containing the patch\n"
		"                   use '-' to disassemble standard input\n"
		"  HINT ...         list of hints for the disassembler\n"
		"\n"
		"options:\n"
		"  -n               suppress offsets and bytecode dumps\n"
		"  -o OUTPUT_FILE   set output file [default=standard output]\n"
		"\n"
		"hints:\n"
		"  The BSP disassembler performs rudimentary static analysis\n"
		"  in order to determine how to interpret data contained inside\n"
		"  a BSP patch. However, the analysis can often miss facts\n"
		"  about control and data flow that would enable inferring data\n"
		"  types. Hints can be used to to manually inform the disassembler\n"
		"  about the type of data that resides at a specific address.\n"
		"\n"
		"  A disassembly hint has this form:"
		"      [@]ADDR[:[*...][TYPE]]\n"
		"  and indicates that data of type TYPE resides at ADDR.\n"
		"  The @ character before ADDR means that a named label should\n"
		"  be placed at ADDR. Prefixing TYPE with an asterisk indicates\n"
		"  pointer indirection: i.e. what resides at ADDR is an address\n"
		"  pointing to data of a given type, not the data itself. Multiple\n"
		"  levels of indirection can be specified by writing multiple\n"
		"  asterisks.\n"
		"\n"
		"  Available TYPEs are:\n"
		"\n"
		"  code             Executable code that may be a target of a\n"
		"                   branch or call instruction (but NOT a child\n"
		"                   patch). This is the default if no TYPE is\n"
		"                   specified.\n"
		"  dh               Halfword (16-bit) value.\n"
		"  dw               Word (32-bit) value, with no other interpretation.\n"
		"  menu             Menu, i.e. a list of pointers to zero-terminated\n"
		"                   strings.\n"
		"  sha1             SHA-1 hash.\n"
		"  ips              IPS patch.\n"
		"  sz               Null-terminated UTF-8 string, displayed\n"
		"                   as a string pseudo-instruction.\n"
		"  +$N              $N bytes of raw data, displayed as a hexdata\n"
		"                   pseudo-instruction.\n"
		"  ?                No type; this can be used to only put a label\n"
		"                   at a given address, or to hint a pointer without\n"
		"                   specifying a type for its target.\n"
		"\n", argv0
	);
	exit(-1);
}

#include "patch_loader.c"

typedef enum {
	CLS_CONTINUE     = 0x10, /* flag: continue */
	CLS_LABELLED     = 0x20, /* flag: labelled */

	CLS_UNKNOWN      = 0x00, /* unknown */
	CLS_OPCODE       = 0x01, /* instruction */
	CLS_OPERAND      = 0x11, /* operand */
	CLS_STRING       = 0x02, /* string */
	CLS_DATA         = 0x03, /* data block */
	CLS_BYTE         = 0x04,
	CLS_WORD         = 0x05,
	CLS_HALF         = 0x06,
	CLS_PTR          = 0x07,
	CLS_IPS          = 0x08,
} cls_t;

typedef uint64_t clsword_t;

#define BITS_PER_CLS 6
#define CLS_MASK ((clsword_t)(1 << BITS_PER_CLS) - 1)
#define CLS_PER_WORD (sizeof(clsword_t) * CHAR_BIT / BITS_PER_CLS)

#define DIV_ROUND_UP(a, b) ((a) / (b) + !!((a) % (b)))

static clsword_t *clses = NULL;

inline static void cls_init(void) {
	clses = calloc(DIV_ROUND_UP((uint64_t)patch_space.limit + 1, CLS_PER_WORD), sizeof(clsword_t));
}

inline static void cls_fini(void) {
	free(clses);
	clses = NULL;
}

inline static cls_t cls_get(uint32_t offset) {
	if (offset > patch_space.limit)
		return CLS_UNKNOWN;
	clsword_t word = clses[offset / CLS_PER_WORD];
	return (word >> (BITS_PER_CLS * (offset % CLS_PER_WORD))) & CLS_MASK;
}

inline static void cls_set(uint32_t offset, cls_t cls) {
	if (offset > patch_space.limit)
		return;
	clsword_t *word = &clses[offset / CLS_PER_WORD];
	*word &= ~(CLS_MASK << (BITS_PER_CLS * (offset % CLS_PER_WORD)));
	*word |= ((clsword_t)cls) << (BITS_PER_CLS * (offset % CLS_PER_WORD));
}

inline static void cls_set_range(uint32_t offset, uint32_t len, cls_t cls) {
	while (len--)
		cls_set(offset++, cls);
}

inline static void dis_put_label(uint32_t addr) {
	if (cls_get(addr) & CLS_CONTINUE)
		return;
	cls_set(addr, cls_get(addr) | CLS_LABELLED);
}

inline static const char *cls_name(cls_t cls) {
	static const char *clsnames[] = {
		[CLS_UNKNOWN               ] = "unknown",
		[CLS_OPCODE                ] = "an instruction",
		[CLS_STRING                ] = "a string",
		[CLS_DATA                  ] = "a data block",
		[CLS_HALF                  ] = "a halfword",
		[CLS_WORD                  ] = "a word",
		[CLS_PTR                   ] = "a pointer",
		[CLS_IPS                   ] = "an embedded IPS patch",

		[CLS_UNKNOWN | CLS_CONTINUE] = "the middle of unknown",
		[CLS_OPCODE  | CLS_CONTINUE] = "the middle of an instruction",
		[CLS_STRING  | CLS_CONTINUE] = "the middle of a string",
		[CLS_DATA    | CLS_CONTINUE] = "the middle of a data block",
		[CLS_HALF    | CLS_CONTINUE] = "the middle of a halfword",
		[CLS_WORD    | CLS_CONTINUE] = "the middle of a word",
		[CLS_PTR     | CLS_CONTINUE] = "the middle of a pointer",
		[CLS_IPS     | CLS_CONTINUE] = "the middle of an embedded IPS patch",
	};

	return clsnames[cls & ~CLS_LABELLED];
}

#define Q_EMPTY { NULL, 0, 0, 0 }

#define Q_TYPE uint32_t
#define Q_QTYPE queue_u32
#define Q_PREFIX q32_
#include "queue.c"

#define q_push(q, v) q32_push(q, v)
#define q_shift(q) q32_shift(q)
#define q_empty(q) q32_empty(q)
#define q_free(q) q32_free(q)

static bool had_diag = false;

#define DIS_ADDR_HINT (~(uint32_t)0)

static void dis_diag(uint32_t off, const char *fmt, ...) {
	if (off == DIS_ADDR_HINT)
		fprintf(stderr, "%s: (command line hint): ", argv0);
	else
		fprintf(stderr, "%s: %s[+0x%x]: ", argv0, patch_fname, off);

	va_list ap;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");

	had_diag = true;
}

static bool cls_compatible(cls_t curr, cls_t want) {
	curr &= ~CLS_LABELLED;
	want &= ~CLS_LABELLED;

	if (curr == CLS_UNKNOWN)
		return true;
	if (curr == want)
		return true;
	if ((curr & ~CLS_CONTINUE) == (want & ~CLS_CONTINUE))
		if ((curr & ~CLS_CONTINUE) == CLS_STRING)
			return true;

	return false;
}

static bool dis_check_unmarked(uint32_t from, uint32_t addr, uint32_t length, const char *prefix, cls_t wanted) {
	while (length--) {
		cls_t cls = cls_get(addr);

		if (!cls_compatible(cls, wanted)) {
			dis_diag(from, "%s: 0x%x is already marked as %s", prefix, addr, cls_name(cls));
			return false;
		}
		wanted |= CLS_CONTINUE;
		addr++;
	}

	return true;
}

static void dis_mark_data(uint32_t from, uint32_t addr, uint32_t length, cls_t cls_start) {
	if (addr > patch_space.limit) {
		dis_diag(from, "bad data reference (0x%x)", addr);
		return;
	}

	if (!length)
		return;

	if (!dis_check_unmarked(from, addr, length, "bad data reference", cls_start))
		return;

	cls_set(addr, cls_start);
	if (length > 1)
		cls_set_range(addr + 1, length - 1, cls_start | CLS_CONTINUE);
}

static void dis_mark_string(uint32_t from, uint32_t addr) {
	if (addr > patch_space.limit) {
		dis_diag(from, "bad string reference (0x%x)", addr);
		return;
	}

	uint32_t end = addr;
	for (;;) {
		if (!patch_space.space[end])
			break;
		if (end++ == patch_space.limit) {
			dis_diag(from, "bad string reference; no terminating NUL (0x%x)", addr);
			return;
		}
	}

	if (!dis_check_unmarked(from, addr, end - addr + 1, "bad string reference", CLS_STRING))
		return;
	cls_set_range(addr, end - addr + 1, CLS_STRING);
}

static void dis_mark_ptr(uint32_t from, uint32_t addr) {
	dis_mark_data(from, addr, 4, CLS_PTR);
}

static void dis_mark_menu(uint32_t from, uint32_t addr) {
	for (;;) {
		if (addr + 3 < addr || addr + 3 > patch_space.limit) {
			dis_diag(from, "bad menu reference (0x%x)", addr);
			return;
		}

		uint32_t saddr = get_le32(patch_space.space + addr);
		if (saddr == 0xffffffff) {
			dis_mark_data(from, addr, 4, CLS_WORD);
			break;
		}

		dis_mark_ptr(from, addr);
		dis_mark_string(addr, saddr);
		dis_put_label(saddr);
		addr += 4;
	}
}

static struct queue_u32 labels = Q_EMPTY;

static void dis_queue_block(uint32_t from, uint32_t addr) {
	if (addr > patch_space.limit) {
		dis_diag(from, "bad control flow beyond the end of the file (0x%x)", addr);
		return;
	}

	cls_t cls = cls_get(addr);

	switch (cls & ~CLS_LABELLED) {
	default:
		dis_diag(from, "bad control flow into %s at 0x%x", cls_name(cls), addr);
		return;
	case CLS_OPCODE:
		return;
	case CLS_UNKNOWN:
		q_push(&labels, addr);
	}
}

static void dis_mark_ips(uint32_t from, uint32_t addr) {
	if (addr > patch_space.limit) {
		dis_diag(from, "bad IPS reference (0x%x)", addr);
		return;
	}

	uint32_t start = addr;

	if (memcmp(&patch_space.space[addr], "PATCH", 5)) {
		dis_diag(from, "bad IPS reference (0x%x)", addr);
		return;
	}
	addr += 5;

	for (;;) {
		if (addr > patch_space.limit) {
			dis_diag(from, "bad IPS reference (0x%x)", addr);
			return;
		}

		addr += 3;
		if (!memcmp(&patch_space.space[addr - 3], "EOF", 3)) {
			break;
		}

		if (addr > patch_space.limit) {
			dis_diag(from, "bad IPS reference (0x%x)", addr);
			return;
		}

		uint16_t len = get_be16(&patch_space.space[addr]);
		addr += 2;
		if (len == 0) {
			addr += 3;
		} else {
			addr += len;
		}
	}

	dis_mark_data(from, start, addr - start, CLS_IPS);
}

static struct queue_u32 jumptabs = Q_EMPTY;

static void dis_jumptab_new(uint32_t addr) {
	q_push(&jumptabs, addr);
}

static void dis_jumptab_grab(void) {
	for (size_t i = jumptabs.off; i < jumptabs.fin; ++i) {
		uint32_t addr = jumptabs.data[i];

		if (addr + 3 < addr)
			continue;
		if (addr + 3 > patch_space.limit)
			continue;

		switch (cls_get(addr) & ~CLS_LABELLED) {
		default:
			continue;
		case CLS_UNKNOWN:
		case CLS_DATA:
		case CLS_PTR:
			dis_mark_ptr(addr, addr);
		}

		uint32_t target = get_le32(patch_space.space + addr);

		switch (cls_get(target) & ~CLS_LABELLED) {
		default:
			if (i == jumptabs.off)
				jumptabs.off++;
			continue;
		case CLS_UNKNOWN:
		case CLS_OPCODE:
			dis_queue_block(addr, target);
			dis_put_label(target);
			jumptabs.data[i] = addr + 4;
		}
	}
}

static bool dump_opcodes = true;

static void dis_load(const char *fname) {
	patch_fname = fname;
	patch_load();
	cls_init();
}

static const char *hint_tags[] = {
	"sz", "sha1", "dh", "dw", "menu", "code", "ips", "?", "", NULL
};

static const char *output_fname = NULL;

static void parse_cmdline(char *argv[]) {
	for (size_t i = 1; argv[i]; i++) {
		const char *arg = argv[i];
		if (arg == NULL)
			break;

		if (arg[0] == '-' && arg[1]) {
			const char *optarg = NULL;

#define TAKE_OPTARG() (arg[1] \
	? (optarg = arg, arg += strlen(arg + 1), ++optarg) \
	: (optarg = argv[++i]))

			for (++arg; *arg; ++arg) {
				switch (*arg) {
				case 'n':
					dump_opcodes = false;
					break;

				case 'o':
					output_fname = TAKE_OPTARG();
					if (!strcmp(output_fname, "-"))
						output_fname = NULL;
					break;

				default:
					show_usage();

				}
			}

#undef TAKE_OPTARG

		} else {
			if (patch_fname == NULL) {
				dis_load(arg);
				continue;
			}

			bool label = false;

			if (*arg == '@') {
				label = true;
				arg++;
			}

			const char *suff;
			unsigned long addr = strtoul(arg, (char **)&suff, 0);

			if (arg == suff || (*suff && *suff != ':' && *suff != '+'))
				goto bad_hint;

			if (addr > patch_space.limit) {
				fprintf(stderr, "%s: hint address 0x%lx is too high\n", argv0, addr);
				exit(-1);
			}

			if (*suff == ':')
				++suff;

			uint32_t from = DIS_ADDR_HINT;
			while (*suff == '*') {
				if (addr > patch_space.limit) {
					fprintf(stderr, "%s: hinted pointer 0x%lx is too high\n", argv0, addr);
					exit(-1);
				}
				dis_mark_ptr(from, addr);
				if (label)
					dis_put_label(addr);
				from = addr;
				addr = get_le32(patch_space.space + addr);
				label = true;
				suff++;
			}

			if (*suff == '+') {
				const char *slen = suff + 1;
				unsigned long len = strtoul(slen, (char **)&suff, 0);
				if (suff == slen || *suff)
					goto bad_hint;

				dis_mark_data(DIS_ADDR_HINT, addr, len, CLS_DATA);
				if (label)
					dis_put_label(addr);
				continue;
			}

			int htyp = 0;
			for (htyp = 0; hint_tags[htyp]; ++htyp) {
				if (!strcmp(suff, hint_tags[htyp]))
					break;
			}

			switch (htyp) {
			case 0:
				dis_mark_string(DIS_ADDR_HINT, addr);
				break;
			case 1:
				dis_mark_data(DIS_ADDR_HINT, addr, 20, CLS_DATA);
				break;
			case 2:
				dis_mark_data(DIS_ADDR_HINT, addr, 2, CLS_HALF);
				break;
			case 3:
				dis_mark_data(DIS_ADDR_HINT, addr, 4, CLS_WORD);
				break;
			case 4:
				dis_mark_menu(DIS_ADDR_HINT, addr);
				break;
			case 5:
			case 8:
				q_push(&labels, addr);
				break;
			case 6:
				dis_mark_ips(DIS_ADDR_HINT, addr);
				break;
			case 7:
				break;
			default:
				goto bad_hint;
			}

			if (label)
				dis_put_label(addr);

			continue;

		bad_hint:
			fprintf(stderr, "%s: invalid hint: '%s'\n", argv0, argv[i]);
			exit(-1);
		}
	}

	if (patch_fname == NULL)
		show_usage();

	q_push(&labels, 0);
}

static void dis_analyse(void) {
	struct bsp_ec ec;

	if (patch_space.space == NULL) {
		dis_diag(0, "patch file is empty");
		return;
	}

	while (!q_empty(&labels)) {
		uint32_t ip = q_shift(&labels);

		if (!bsp_try(&ec)) for (;;) {
			struct bsp_opcode opc;

			cls_t cls = cls_get(ip);
			if ((cls & ~CLS_LABELLED) != CLS_UNKNOWN) {
				if ((cls & ~CLS_LABELLED) != CLS_OPCODE)
					dis_diag(ip, "bad control flow into %s", cls_name(cls));
				break;
			}

			size_t sz = bsp_ps_fetchop(&ec, &patch_space, ip, &opc);

			for (size_t i = 0; i < sz; ++i) {
				cls_t vcls = cls_get(ip + i);
				if ((vcls & ~CLS_LABELLED) != CLS_UNKNOWN) {
					dis_diag(ip, "operand spills over into %s", cls_name(vcls));
					goto next_label;
				}
			}

			if ((cls & ~CLS_LABELLED) == CLS_UNKNOWN)
				cls_set(ip, CLS_OPCODE | (cls & CLS_LABELLED));
			for (size_t i = 1; i < sz; ++i) {
				cls_set(ip + i, CLS_OPERAND);
			}

			bsp_opflags_t fl = bsp_op_get_flags(&opc);
			bsp_opsems_t sems = bsp_op_get_sems(&opc);

			uint32_t data_ptr = -1;
			for (size_t i = 0; i < BSP_OPNUM; ++i) {
				if (opc.optyp[i] != BSP_OPD_IMM32)
					continue;

				switch (BSP_OPSEM_AT(sems, i)) {
				case BSP_OPSEM_DIVISOR:
					if (opc.opval[i] == 0)
						fl |= BSP_OPFLAG_STOPS_FLOW;
					break;
				case BSP_OPSEM_USV:
					if (opc.opval[i] > 0x10ffff)
						fl |= BSP_OPFLAG_STOPS_FLOW;
					else if ((opc.opval[i] & 0xd800) == 0xd800)
						fl |= BSP_OPFLAG_STOPS_FLOW;
					break;
				case BSP_OPSEM_PTR_SHA1:
					dis_mark_data(ip, opc.opval[i], 20, CLS_DATA);
					dis_put_label(opc.opval[i]);
					break;
				case BSP_OPSEM_PTR_STR:
					dis_mark_string(ip, opc.opval[i]);
					dis_put_label(opc.opval[i]);
					break;
				case BSP_OPSEM_PTR_CODE:
					dis_queue_block(ip, opc.opval[i]);
					dis_put_label(opc.opval[i]);
					break;
				case BSP_OPSEM_PTR_MENU:
					dis_mark_menu(ip, opc.opval[i]);
					dis_put_label(opc.opval[i]);
					break;
				case BSP_OPSEM_PTR_BSP:
				case BSP_OPSEM_PTR_DATA:
					data_ptr = opc.opval[i];
					dis_put_label(opc.opval[i]);
					break;
				case BSP_OPSEM_LENGTH:
					// XXX: we exploit the fact that in all currently defined opcodes,
					// data length follows data pointer; this may fail in the future!
					if (data_ptr == -1)
						break;
					dis_mark_data(ip, data_ptr, opc.opval[i], CLS_DATA);
					break;
				case BSP_OPSEM_PTR_DATA8:
					dis_mark_data(ip, opc.opval[i], 1, CLS_BYTE);
					dis_put_label(opc.opval[i]);
					break;
				case BSP_OPSEM_PTR_DATA16:
					dis_mark_data(ip, opc.opval[i], 2, CLS_HALF);
					dis_put_label(opc.opval[i]);
					break;
				case BSP_OPSEM_PTR_DATA32:
					dis_mark_data(ip, opc.opval[i], 4, CLS_WORD);
					dis_put_label(opc.opval[i]);
					break;
				case BSP_OPSEM_PTR_IPS:
					dis_mark_ips(ip, opc.opval[i]);
					dis_put_label(opc.opval[i]);
					break;
				default: ;
				}
			}

			ip += sz;

			if (fl & BSP_OPFLAG_JUMP_TABLE) {
				dis_jumptab_new(ip);
				break;
			}

			if (fl & BSP_OPFLAG_STOPS_FLOW)
				break;
		} else {
			dis_diag(ip, "failed to fetch opcode: %s", ec.fatal_msg);
			bsp_ec_clear(&ec);
		}

	next_label: ;

		if (q_empty(&labels)) {
			dis_jumptab_grab();
		}
	}

	q_free(&jumptabs);
	q_free(&labels);
}

static void fput_addr(FILE *outf, uint32_t offset) {
	static const char *cls_label_prefix[0x0f] = {
		"unk",
		"label",
		"str",
		"data",
		"byte",
		"word",
		"half",
		"ptr",
		"ips",
	};

	cls_t cls = cls_get(offset);

	if (cls & CLS_LABELLED) {
		fprintf(outf, "%s_%08x", cls_label_prefix[cls & ~CLS_LABELLED], offset);
	} else {
		fprintf(outf, "0x%08x", offset);
	}
}

#include "hexdump.c"

static void dis_print(FILE *outf) {
	if (patch_space.space == NULL)
		return;

	for (uint32_t offset = 0; offset <= patch_space.limit && (offset + 1); ) {
		cls_t cls = cls_get(offset);

		if (cls & CLS_LABELLED) {
			fput_addr(outf, offset);
			fprintf(outf, ":\n");
		}

		if (dump_opcodes)
			fprintf(outf, "%08x  ", offset);

		switch (cls & ~CLS_LABELLED) {

		case CLS_OPCODE: {
			uint32_t ip = offset;
			struct bsp_opcode opc;

			// XXX: NULL? really?
			ip += bsp_ps_fetchop(NULL, &patch_space, ip, &opc);

			const char *mnemonic = bsp_op_get_mnemonic(&opc);
			bsp_opsems_t sems = bsp_op_get_sems(&opc);

			fhexdump(outf, patch_space.space + offset, dump_opcodes ? ip - offset : 0, 12);

			fprintf(outf, "%-18s ", mnemonic);

			bool comma = false;

			for (int i = 0; i < BSP_OPNUM; ++i) {
				if (opc.optyp[i] == BSP_OPD_NONE)
					continue;

				if (comma)
					fprintf(outf, ", ");
				else
					comma = true;

				switch (opc.optyp[i]) {
				default:
				case BSP_OPD_NONE:
					abort(); /* handled above */
				case BSP_OPD_RREG:
				case BSP_OPD_MREG:
				case BSP_OPD_WREG:
					fprintf(outf, "#%u", opc.opval[i]);
					continue;
				case BSP_OPD_IMM8:
					fprintf(outf, "0x%02x", opc.opval[i]);
					continue;
				case BSP_OPD_IMM16:
					fprintf(outf, "0x%04x", opc.opval[i]);
					continue;
				case BSP_OPD_IMM32: ;
				}

				switch (BSP_OPSEM_AT(sems, i)) {
				case BSP_OPSEM_STACK:
					fprintf(outf, "%+d", opc.opval[i]);
					break;
				case BSP_OPSEM_PTR_CODE:
				case BSP_OPSEM_PTR_STR:
				case BSP_OPSEM_PTR_SHA1:
				case BSP_OPSEM_PTR_IPS:
				case BSP_OPSEM_PTR_DATA:
				case BSP_OPSEM_PTR_DATA8:
				case BSP_OPSEM_PTR_DATA16:
				case BSP_OPSEM_PTR_DATA32:
				case BSP_OPSEM_PTR_BSP:
				case BSP_OPSEM_PTR_MENU: {
					fput_addr(outf, opc.opval[i]);
					break;
				}
				default:
					fprintf(outf, "0x%08x", opc.opval[i]);
					break;
				}
			}

			fprintf(outf, "\n");

			offset = ip;
			break;
		}

		case CLS_STRING:
		case CLS_STRING | CLS_CONTINUE: {
			uint32_t offset_start = offset;
			while (cls_get(++offset) == CLS_STRING)
				if (patch_space.space[offset - 1] == 0)
					break;

			fhexdump(outf, NULL, 0, 12);

			fprintf(outf, "%-18s ", "string");
			fprintf(outf, "\"");
			while (offset_start < offset) {
				char ch = (char)patch_space.space[offset_start++];
				if (!ch)
					break;
				fprintf(outf, "%c%s", ch, ch == '"' ? "\"" : "");
			}
			fprintf(outf, "\"\n");
			break;
		}

		case CLS_PTR: {
			fhexdump(outf, patch_space.space + offset, dump_opcodes ? 4 : 0, 12);

			uint32_t value = get_le32(patch_space.space + offset);
			offset += 4;

			fprintf(outf, "%-18s ", "dw");
			fput_addr(outf, value);
			fprintf(outf, "\n");
			break;
		}

		case CLS_WORD: {
			fhexdump(outf, patch_space.space + offset, dump_opcodes ? 4 : 0, 12);

			uint32_t value = get_le32(patch_space.space + offset);
			offset += 4;

			fprintf(outf, "%-18s 0x%08x\n", "dw", value);
			break;
		}

		/* XXX */
		case CLS_HALF: {
			fhexdump(outf, patch_space.space + offset, dump_opcodes ? 2 : 0, 12);

			uint16_t value = get_le16(patch_space.space + offset);
			offset += 2;

			fprintf(outf, "%-18s 0x%04x\n", "dh", value);
			break;
		}

		case CLS_IPS:
		case CLS_DATA: {
			uint32_t offset_start = offset;
			uint32_t offset_cur = offset;
			while (cls_get(++offset) & CLS_CONTINUE)
				if (offset == 0xffffffff)
					break;

			do {
				fhexdump(outf, NULL, 0, 12);
				fprintf(outf, "%-18s ", "hexdata");
				while (offset_cur < offset) {
					fprintf(outf, "%02x", patch_space.space[offset_cur++]);
					if ((offset_cur - offset_start) % 32 == 0)
						break;
				}
				fprintf(outf, "\n");
				if (offset_cur < offset)
					if (dump_opcodes)
						fprintf(outf, "%08x  ", offset_cur);
			} while (offset_cur < offset);
			break;
		}

		case CLS_BYTE:
		default: {
			fhexdump(outf, NULL, 0, 12);

			fprintf(outf, "%-18s ", "db");
			fprintf(outf, "0x%02x", patch_space.space[offset]);
			if (isprint(patch_space.space[offset])) {
				fprintf(outf, " ; '%c'", patch_space.space[offset]);
			}
			offset++;
			fprintf(outf, "\n");
			break;
		}

		}
	}
}

int main(int argc, char **argv) {
	argv0 = argv[0];
	parse_cmdline(argv);

	dis_analyse();

	FILE *outf = stdout;
	if (output_fname != NULL) {
		outf = fopen(output_fname, "wt");
		if (outf == NULL) {
			perror(output_fname);
			return 1;
		}
	}

	dis_print(outf);

	if (outf != stdout)
		fclose(outf);

	cls_fini();
	patch_unload();

	return had_diag;
}
