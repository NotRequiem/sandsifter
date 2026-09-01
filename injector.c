#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include <fcntl.h>
#include <io.h>

#if defined(__x86_64__) || defined(_M_X64)
	#define ARCH_X64 1
	#define CS_MODE CS_MODE_64
#else
	#define ARCH_X64 0
	#define CS_MODE CS_MODE_32
#endif

#define USE_CAPSTONE true

#if USE_CAPSTONE
	#include <capstone/capstone.h>
	csh capstone_handle;
	cs_insn *capstone_insn;
#endif

#define SIGILL  4
#define SIGTRAP 5
#define SIGBUS  7
#define SIGFPE  8
#define SIGSEGV 11

#define UD2_SIZE  2
#define PAGE_SIZE 4096
#define ARENA_SIZE (PAGE_SIZE * 2)

#define MAX_INSN_LENGTH 15

#define TICK_MASK 0xffff
#define RAW_REPORT_INSN_BYTES 16
#define RAW_REPORT_DISAS_MNE false
#define RAW_REPORT_DISAS_MNE_BYTES 16
#define RAW_REPORT_DISAS_OPS false
#define RAW_REPORT_DISAS_OPS_BYTES 32
#define RAW_REPORT_DISAS_LEN true
#define RAW_REPORT_DISAS_VAL true

#define MAX_BLACKLIST 128

typedef enum { BRUTE, RAND, TUNNEL, DRIVEN } search_mode_t;
typedef enum { TEXT, RAW } output_t;

struct {
	bool allow_dup_prefix; 
	int max_prefix;
	int brute_depth;
	long seed;
	int range_bytes;
	bool show_tick;
	int jobs;
	bool force_core;
	int core;
	bool enable_null_access;
	bool nx_support;
} config = {
	.allow_dup_prefix = false,
	.max_prefix = 0,
	.brute_depth = 4,
	.seed = 0,
	.range_bytes = 0,
	.show_tick = false,
	.jobs = 1,
	.force_core = false,
	.core = 0,
	.enable_null_access = false,
	.nx_support = true,
};

search_mode_t mode = TUNNEL;
output_t output = TEXT;

void* arena_buffer = NULL;
char* packet = NULL;
uint8_t* guard_boundary = NULL;
static uint8_t dummy_stack_area[65536] __attribute__ ((aligned(4096)));
static uint8_t scratch_area[65536] __attribute__ ((aligned(4096)));

typedef struct {
	uint8_t bytes[MAX_INSN_LENGTH];
	int len;
} insn_t;

typedef struct {
	insn_t i;
	int index;
	int last_len;
} inj_t;
inj_t inj;

static const insn_t null_insn = {0};
static CONTEXT fault_context;
static bool have_state = false;
static uintptr_t last_fault_addr = 0;
static uintptr_t last_fault_ip = 0;

#pragma pack(push, 1)
typedef struct {
	uint32_t valid;
	uint32_t length;
	uint32_t signum;
	uint32_t si_code;
	uint32_t addr;
} result_t;

typedef struct {
#if RAW_REPORT_DISAS_MNE
	char mne[RAW_REPORT_DISAS_MNE_BYTES];
#endif
#if RAW_REPORT_DISAS_OPS
	char ops[RAW_REPORT_DISAS_OPS_BYTES];
#endif
#if RAW_REPORT_DISAS_LEN
	int len;
#endif
#if RAW_REPORT_DISAS_VAL
	int val;
#endif
} disas_t;
#pragma pack(pop)

result_t result;
disas_t disas;

typedef struct {
	uint8_t* opcode;
	int len;
	char* reason;
} ignore_op_t;

ignore_op_t opcode_blacklist[MAX_BLACKLIST] = {
	{ (uint8_t*)"\x0f\x34",     2, "sysenter" },
	{ (uint8_t*)"\x0f\x35",     2, "sysexit" },
	{ (uint8_t*)"\x0f\x05",     2, "syscall" },
	{ (uint8_t*)"\x0f\x07",     2, "sysret" },
	{ (uint8_t*)"\x0f\xa1",     2, "pop fs" },
	{ (uint8_t*)"\x0f\xa9",     2, "pop gs" },
	{ (uint8_t*)"\x0f\xa0",     2, "push fs" },
	{ (uint8_t*)"\x0f\xa8",     2, "push gs" },
	{ (uint8_t*)"\x0f\x01\xc8", 3, "monitor" },
	{ (uint8_t*)"\x0f\x01\xc9", 3, "mwait" },
	{ (uint8_t*)"\x0f\x01\xf8", 3, "swapgs" },
	{ (uint8_t*)"\x0f\xae",     2, "xsave/xrstor/fsgsbase" },
	{ (uint8_t*)"\x0f\xc7\xec", 3, "wrpkru" },
	{ (uint8_t*)"\x0f\xc7\xed", 3, "wrpkru" },
	{ (uint8_t*)"\x0f\xc7\xee", 3, "wrpkru" },
	{ (uint8_t*)"\x0f\xc7\xef", 3, "wrpkru" },
	{ (uint8_t*)"\x0f\xaa",     2, "rsm" },
	{ (uint8_t*)"\x0f\xb2",     2, "lss" },
	{ (uint8_t*)"\x0f\xb4",     2, "lfs" },
	{ (uint8_t*)"\x0f\xb5",     2, "lgs" },
	{ (uint8_t*)"\x8e",         1, "mov seg" },
	{ (uint8_t*)"\xcd\x29",     2, "fastfail" },
	{ (uint8_t*)"\xcc",         1, "int3" },
	{ (uint8_t*)"\xce",         1, "into" },
	{ (uint8_t*)"\xf1",         1, "icebp" },
	{ (uint8_t*)"\xc8",         1, "enter" },
	{ (uint8_t*)"\xc7\xf8",     2, "xbegin" },
	{ (uint8_t*)"\x0f\xb9",     2, "ud2" },
	{ (uint8_t*)"\xc2",         1, "ret imm16" },
	{ (uint8_t*)"\xc3",         1, "ret" },
	{ (uint8_t*)"\xca",         1, "retf imm16" },
	{ (uint8_t*)"\xcb",         1, "retf" },
	{ (uint8_t*)"\xcf",         1, "iret" },
	{ NULL, 0, NULL }
};

typedef struct {
	char* prefix;
	char* reason;
} ignore_pre_t;

ignore_pre_t prefix_blacklist[] = {
	{ "\x65", "gs" },
	{ "\x64", "fs" },
	{ NULL, NULL }
};

typedef struct { insn_t start; insn_t end; bool started; } range_t;
insn_t* range_marker = NULL;
range_t search_range = {0};
range_t total_range = {
	.start = {.bytes = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}, .len = 0},
	.end   = {.bytes = {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff}, .len = 0},
	.started = false
};

HANDLE pool_mutex = NULL;
HANDLE output_mutex = NULL;
HANDLE hMapRange = NULL;

static char* optarg = NULL;
static int optind = 1;
static int opterr = 1;
static int optopt = '?';

extern char resume;
static int expected_length;
static void* current_exec_addr = NULL;

bool is_prefix(uint8_t x);
bool has_opcode(const uint8_t* op, int op_len);
bool is_backward_branch(const uint8_t* b);
bool is_indirect_branch(const uint8_t* b);
bool is_rip_relative_self_modify(const uint8_t* b);
bool is_branch_insn(const uint8_t* b, int* branch_len);
bool modifies_sp(const uint8_t* b);
void print_mc(FILE* f, int length);
void give_result(FILE* f);
int prefix_count(void);
bool has_dup_prefix(void);
void execute_target(void* addr);
bool move_next_instruction(void);
bool move_next_range(void);
void init_config(int argc, char** argv);
void pin_core(void);
void tick(void);
void pretext(void);

int getopt(int argc, char* const argv[], const char* optstring)
{
	static int optpos = 1;
	if (optind >= argc || argv[optind] == NULL || argv[optind][0] != '-' || argv[optind][1] == '\0') {
		return -1;
	}
	if (strcmp(argv[optind], "--") == 0) {
		optind++;
		return -1;
	}
	char c = argv[optind][optpos];
	const char* p = strchr(optstring, c);
	if (!p || c == ':') {
		optopt = c;
		if (argv[optind][++optpos] == '\0') {
			optind++;
			optpos = 1;
		}
		return '?';
	}
	if (p[1] == ':') {
		if (argv[optind][optpos + 1] != '\0') {
			optarg = &argv[optind][optpos + 1];
			optind++;
			optpos = 1;
		} else if (optind + 1 < argc) {
			optarg = argv[optind + 1];
			optind += 2;
			optpos = 1;
		} else {
			optopt = c;
			optind++;
			optpos = 1;
			return ':';
		}
	} else {
		if (argv[optind][++optpos] == '\0') {
			optind++;
			optpos = 1;
		}
		optarg = NULL;
	}
	return c;
}

void sync_fprintf(FILE* f, const char *format, ...)
{
	va_list args;
	va_start(args, format);
	WaitForSingleObject(output_mutex, INFINITE);
	vfprintf(f, format, args);
	ReleaseMutex(output_mutex);
	va_end(args);
}

void sync_fwrite(const void* ptr, size_t size, size_t count, FILE* f)
{
	WaitForSingleObject(output_mutex, INFINITE);
	fwrite(ptr, size, count, f);
	ReleaseMutex(output_mutex);
}

void sync_fflush(FILE* f, bool force)
{
	WaitForSingleObject(output_mutex, INFINITE);
	fflush(f);
	ReleaseMutex(output_mutex);
}

void zero_insn_end(insn_t* insn, int marker)
{
	int i;
	for (i = marker; i < MAX_INSN_LENGTH; i++) {
		insn->bytes[i] = 0;
	}
}

bool increment_range(insn_t* insn, int marker)
{
	int i = marker - 1;
	zero_insn_end(insn, marker);

	if (i >= 0) {
		insn->bytes[i]++;
		while (insn->bytes[i] == 0) {
			i--;
			if (i < 0) {
				break;
			}
			insn->bytes[i]++;
		}
	}

	insn->len = marker;
	return i >= 0;
}

void initialize_ranges(void)
{
	if (range_marker == NULL) {
		hMapRange = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, sizeof(insn_t), NULL);
		assert(hMapRange != NULL);
		range_marker = (insn_t*)MapViewOfFile(hMapRange, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(insn_t));
		assert(range_marker != NULL);
		*range_marker = total_range.start;
	}
}

void free_ranges(void)
{
	if (range_marker != NULL) {
		UnmapViewOfFile(range_marker);
		range_marker = NULL;
	}
	if (hMapRange != NULL) {
		CloseHandle(hMapRange);
		hMapRange = NULL;
	}
}

bool move_next_range(void)
{
	bool res = true;

	switch (mode) {
		case RAND:
		case DRIVEN:
			if (search_range.started) {
				res = false;
			}
			else {
				search_range = total_range;
			}
			break;
		case BRUTE:
		case TUNNEL:
			WaitForSingleObject(pool_mutex, INFINITE);
			search_range.started = false;
			if (memcmp(range_marker->bytes, total_range.end.bytes, sizeof(range_marker->bytes)) == 0) {
				res = false;
			}
			else {
				search_range.start = *range_marker;
				search_range.end = *range_marker;
				if (!increment_range(&search_range.end, config.range_bytes)) {
					search_range.end = total_range.end;
				}
				else if (memcmp(search_range.end.bytes, total_range.end.bytes, sizeof(search_range.end.bytes)) > 0) {
					search_range.end = total_range.end;
				}
				*range_marker = search_range.end;
			}
			ReleaseMutex(pool_mutex);
			break;
		default:
			assert(0);
	}

	return res;
}

#if USE_CAPSTONE
int print_asm(FILE* f)
{
	if (output == TEXT) {
		uint8_t* code = inj.i.bytes;
		size_t code_size = MAX_INSN_LENGTH;
		uint64_t address = (uintptr_t)packet;
	
		if (cs_disasm_iter(capstone_handle, (const uint8_t**)&code, &code_size, &address, capstone_insn)) {
			sync_fprintf(f, "%10s %-45s (%2d)", capstone_insn[0].mnemonic, capstone_insn[0].op_str, (int)(address - (uintptr_t)packet));
		}
		else {
			sync_fprintf(f, "%10s %-45s (%2d)", "(unk)", " ", (int)(address - (uintptr_t)packet));
		}
		expected_length = (int)(address - (uintptr_t)packet);
	}
	return 0;
}
#endif

bool is_prefix(uint8_t x)
{
	return 
		x == 0xf0 ||
		x == 0xf2 ||
		x == 0xf3 ||
		x == 0x2e ||
		x == 0x36 ||
		x == 0x3e ||
		x == 0x26 ||
		x == 0x64 ||
		x == 0x65 ||
		x == 0x66 ||
		x == 0x67
#if ARCH_X64
		|| (x >= 0x40 && x <= 0x4f)
#endif
		;
}

bool is_branch_insn(const uint8_t* b, int* branch_len)
{
	int idx = 0;
	while (idx < MAX_INSN_LENGTH && is_prefix(b[idx])) idx++;
	if (idx >= MAX_INSN_LENGTH) return false;

	uint8_t op = b[idx];

	if ((op >= 0x70 && op <= 0x7f) || op == 0xeb || (op >= 0xe0 && op <= 0xe3)) {
		if (branch_len) *branch_len = idx + 2;
		return true;
	}

	if (op == 0x0f && idx + 1 < MAX_INSN_LENGTH) {
		uint8_t op2 = b[idx + 1];
		if (op2 >= 0x80 && op2 <= 0x8f) {
			if (branch_len) *branch_len = idx + 6;
			return true;
		}
	}

	if (op == 0xe9 || op == 0xe8) {
		if (branch_len) *branch_len = idx + 5;
		return true;
	}

	return false;
}

bool is_backward_branch(const uint8_t* b)
{
	int idx = 0;
	while (idx < MAX_INSN_LENGTH && is_prefix(b[idx])) idx++;
	if (idx >= MAX_INSN_LENGTH) return false;

	uint8_t op = b[idx];

	if ((op >= 0x70 && op <= 0x7f) || op == 0xeb || (op >= 0xe0 && op <= 0xe3)) {
		if (idx + 1 < MAX_INSN_LENGTH) {
			int8_t disp8 = (int8_t)b[idx + 1];
			if (disp8 <= 0) {
				return true;
			}
		}
	}

	if (op == 0x0f && idx + 1 < MAX_INSN_LENGTH) {
		uint8_t op2 = b[idx + 1];
		if (op2 >= 0x80 && op2 <= 0x8f) {
			if (idx + 5 < MAX_INSN_LENGTH) {
				int32_t disp32 = (int32_t)(b[idx + 2] | (b[idx + 3] << 8) | 
				                          (b[idx + 4] << 16) | (b[idx + 5] << 24));
				if (disp32 <= 0) {
					return true;
				}
			}
		}
	}

	if (op == 0xe9 && idx + 4 < MAX_INSN_LENGTH) {
		int32_t disp32 = (int32_t)(b[idx + 1] | (b[idx + 2] << 8) | 
		                          (b[idx + 3] << 16) | (b[idx + 4] << 24));
		if (disp32 <= 0) {
			return true;
		}
	}

	return false;
}

bool is_indirect_branch(const uint8_t* b)
{
	int idx = 0;
	while (idx < MAX_INSN_LENGTH && is_prefix(b[idx])) idx++;
	if (idx >= MAX_INSN_LENGTH) return false;

	uint8_t op = b[idx];

	if (op == 0xff && idx + 1 < MAX_INSN_LENGTH) {
		uint8_t modrm = b[idx + 1];
		uint8_t reg = (modrm >> 3) & 0x07;
		if (reg >= 2 && reg <= 5) {
			return true;
		}
	}

	if (op == 0xea || op == 0x9a) {
		return true;
	}

	return false;
}

bool is_rip_relative_self_modify(const uint8_t* b)
{
#if ARCH_X64
	int idx = 0;
	while (idx < MAX_INSN_LENGTH && is_prefix(b[idx])) idx++;
	if (idx >= MAX_INSN_LENGTH) return false;

	uint8_t op = b[idx];
	int modrm_idx = -1;

	if (op == 0x0f) {
		if (idx + 1 >= MAX_INSN_LENGTH) return false;
		uint8_t op2 = b[idx + 1];
		if (op2 == 0x38 || op2 == 0x3a) modrm_idx = idx + 3;
		else modrm_idx = idx + 2;
	} else if (op == 0xc5) {
		modrm_idx = idx + 2;
	} else if (op == 0xc4 || op == 0x8f || op == 0x62) {
		modrm_idx = idx + 3;
	} else {
		modrm_idx = idx + 1;
	}

	if (modrm_idx >= 0 && modrm_idx < MAX_INSN_LENGTH) {
		uint8_t modrm = b[modrm_idx];
		if ((modrm & 0xc7) == 0x05) {
			if (modrm_idx + 4 <= MAX_INSN_LENGTH) {
				int32_t disp32 = (int32_t)(b[modrm_idx + 1] | 
				                          (b[modrm_idx + 2] << 8) | 
				                          (b[modrm_idx + 3] << 16) | 
				                          (b[modrm_idx + 4] << 24));
				if (disp32 >= -64 && disp32 <= 64) {
					return true;
				}
			}
		}
	}
#endif
	return false;
}

bool modifies_sp(const uint8_t* b)
{
#if USE_CAPSTONE
	uint8_t* code = (uint8_t*)b;
	size_t code_size = MAX_INSN_LENGTH;
	uint64_t address = (uintptr_t)packet;
	if (cs_disasm_iter(capstone_handle, (const uint8_t**)&code, &code_size, &address, capstone_insn)) {
		if (capstone_insn->detail) {
			for (int r = 0; r < capstone_insn->detail->regs_write_count; r++) {
				uint16_t reg_w = capstone_insn->detail->regs_write[r];
				if (reg_w == X86_REG_RSP || reg_w == X86_REG_ESP || reg_w == X86_REG_SP || reg_w == X86_REG_SPL) {
					return true;
				}
			}
			for (int op_i = 0; op_i < capstone_insn->detail->x86.op_count; op_i++) {
				cs_x86_op* op_desc = &capstone_insn->detail->x86.operands[op_i];
				if (op_desc->type == X86_OP_REG) {
					if (op_desc->reg == X86_REG_RSP || op_desc->reg == X86_REG_ESP || 
					    op_desc->reg == X86_REG_SP || op_desc->reg == X86_REG_SPL) {
						if (op_desc->access & CS_AC_WRITE) {
							return true;
						}
					}
				}
			}
		}
	}
#endif

	int idx = 0;
	while (idx < MAX_INSN_LENGTH && is_prefix(b[idx])) idx++;
	if (idx >= MAX_INSN_LENGTH) return false;
	
	uint8_t op = b[idx];

	if ((op >= 0x50 && op <= 0x5f) || op == 0x68 || op == 0x6a || 
	    op == 0x9c || op == 0x9d || op == 0xc2 || op == 0xc3 || 
	    op == 0xc8 || op == 0xc9 || op == 0xca || op == 0xcb || 
	    op == 0xcc || op == 0xcd || op == 0xce || op == 0xcf || 
	    op == 0xe8 || op == 0xbc || op == 0x9a) {
		return true;
	}

	int modrm_idx = -1;
	if (op == 0x0f) {
		if (idx + 1 >= MAX_INSN_LENGTH) return false;
		uint8_t op2 = b[idx + 1];
		if (op2 == 0x38 || op2 == 0x3a) modrm_idx = idx + 3;
		else modrm_idx = idx + 2;
	} else if (op == 0xc5) {
		modrm_idx = idx + 2;
	} else if (op == 0xc4 || op == 0x8f || op == 0x62) {
		modrm_idx = idx + 3;
	} else {
		modrm_idx = idx + 1;
	}

	if (modrm_idx >= 0 && modrm_idx < MAX_INSN_LENGTH) {
		uint8_t modrm = b[modrm_idx];
		uint8_t mod = modrm & 0xc0;
		uint8_t reg = (modrm >> 3) & 0x07;
		uint8_t rm = modrm & 0x07;

		if (mod == 0xc0 && rm == 4) return true;
		if (op == 0x8d && reg == 4) return true;
	}

	return false;
}

void print_mc(FILE* f, int length)
{
	int i;
	bool p = false;
	if (!is_prefix(inj.i.bytes[0])) {
		sync_fprintf(f, " ");
		p = true;
	}
	for (i = 0; i < length && i < MAX_INSN_LENGTH; i++) {
		sync_fprintf(f, "%02x", inj.i.bytes[i]);
		if (!p && i < MAX_INSN_LENGTH - 1 && is_prefix(inj.i.bytes[i]) && !is_prefix(inj.i.bytes[i + 1])) {
			sync_fprintf(f, " ");
			p = true;
		}
	}
}

int prefix_count(void)
{
	int i;
	for (i = 0; i < MAX_INSN_LENGTH; i++) {
		if (!is_prefix(inj.i.bytes[i])) {
			return i;
		}
	}
	return i;
}

bool has_dup_prefix(void)
{
	int i;
	int byte_count[256];
	memset(byte_count, 0, 256 * sizeof(int));

	for (i = 0; i < MAX_INSN_LENGTH; i++) {
		if (is_prefix(inj.i.bytes[i])) {
			byte_count[inj.i.bytes[i]]++;
		}
		else {
			break;
		}
	}

	for (i = 0; i < 256; i++) {
		if (byte_count[i] > 1) {
			return true;
		}
	}

	return false;
}

bool has_opcode(const uint8_t* op, int op_len)
{
	int i, j;
	for (i = 0; i < MAX_INSN_LENGTH; i++) {
		if (!is_prefix(inj.i.bytes[i])) {
			if (i + op_len > MAX_INSN_LENGTH) {
				return false;
			}
			for (j = 0; j < op_len; j++) {
				if (inj.i.bytes[i + j] != op[j]) {
					return false;
				}
			}
			return true;
		}
	}
	return false;
}

bool has_prefix(uint8_t* pre)
{
	int i, j;
	for (i = 0; i < MAX_INSN_LENGTH; i++) {
		if (is_prefix(inj.i.bytes[i])) {
			j = 0;
			do {
				if (inj.i.bytes[i] == pre[j]) {
					return true;
				}
				j++;
			} while (pre[j]);
		}
		else {
			return false;
		}
	}
	return false;
}

void execute_target(void* addr)
{
	current_exec_addr = addr;

	if (!have_state) {
		__asm__ __volatile__ ("ud2\n\t");
		have_state = true;
	}

	uintptr_t safe_target = (uintptr_t)(scratch_area + 32768);

	uintptr_t* stk = (uintptr_t*)dummy_stack_area;
	for (size_t s = 0; s < sizeof(dummy_stack_area) / sizeof(uintptr_t); s++) {
		stk[s] = (uintptr_t)addr + MAX_INSN_LENGTH;
	}

	__asm__ __volatile__ ("emms\n\t");

#if ARCH_X64
	__asm__ __volatile__ (
		"movq %0, %%r11 \n\t"
		"movq %1, %%rax \n\t"
		"movq %1, %%rbx \n\t"
		"movq %1, %%rcx \n\t"
		"movq %1, %%rdx \n\t"
		"movq %1, %%rsi \n\t"
		"movq %1, %%rdi \n\t"
		"movq %1, %%rbp \n\t"
		"movq %1, %%r8  \n\t"
		"movq %1, %%r9  \n\t"
		"movq %1, %%r10 \n\t"
		"movq %1, %%r12 \n\t"
		"movq %1, %%r13 \n\t"
		"movq %1, %%r14 \n\t"
		"movq %1, %%r15 \n\t"
		"leaq dummy_stack_area+32768(%%rip), %%rsp \n\t"
		"jmp *%%r11 \n\t"
		:
		: "r"(addr), "r"(safe_target)
		: "memory"
	);
#else
	__asm__ __volatile__ (
		"movl %0, %%edx \n\t"
		"movl %1, %%eax \n\t"
		"movl %1, %%ebx \n\t"
		"movl %1, %%ecx \n\t"
		"movl %1, %%esi \n\t"
		"movl %1, %%edi \n\t"
		"movl %1, %%ebp \n\t"
		"leal dummy_stack_area+32768, %%esp \n\t"
		"jmp *%%edx \n\t"
		:
		: "r"(addr), "r"(safe_target)
		: "memory"
	);
#endif

	__asm__ __volatile__ (
		".globl resume \n\t"
		"resume:       \n\t"
	);
}

LONG WINAPI veh_handler(PEXCEPTION_POINTERS pExceptionInfo)
{
	__asm__ __volatile__ ("emms\n\t");

	if (!have_state) {
		fault_context = *pExceptionInfo->ContextRecord;
		fault_context.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
#if ARCH_X64
		pExceptionInfo->ContextRecord->Rip += UD2_SIZE;
#else
		pExceptionInfo->ContextRecord->Eip += UD2_SIZE;
#endif
		have_state = true;
		return EXCEPTION_CONTINUE_EXECUTION;
	}

#if ARCH_X64
	uintptr_t fault_ip = (uintptr_t)pExceptionInfo->ContextRecord->Rip;
#else
	uintptr_t fault_ip = (uintptr_t)pExceptionInfo->ContextRecord->Eip;
#endif

	DWORD code = pExceptionInfo->ExceptionRecord->ExceptionCode;
	uint32_t signum = 0;
	uint32_t si_code = 0;
	uint32_t addr = (uint32_t)-1;
	uintptr_t fault_addr = 0;
	int fault_offset = (int)(fault_ip - (uintptr_t)current_exec_addr);
	int insn_length = 0;

	if (pExceptionInfo->ExceptionRecord->NumberParameters > 1) {
		fault_addr = (uintptr_t)pExceptionInfo->ExceptionRecord->ExceptionInformation[1];
	}

	last_fault_ip = fault_ip;
	last_fault_addr = fault_addr;

	if (code == EXCEPTION_ACCESS_VIOLATION || code == EXCEPTION_IN_PAGE_ERROR) {
		if (fault_addr == (uintptr_t)guard_boundary && fault_ip == (uintptr_t)guard_boundary && fault_offset > 0) {
			signum = SIGTRAP;
			si_code = 1;
			insn_length = fault_offset;
			addr = 0;
		}
		else {
			signum = SIGSEGV;
			si_code = (uint32_t)pExceptionInfo->ExceptionRecord->ExceptionInformation[0];
			addr = (uint32_t)fault_addr;
			insn_length = fault_offset > 0 ? fault_offset : 0;
		}
	}
	else if (code == EXCEPTION_ILLEGAL_INSTRUCTION || code == EXCEPTION_PRIV_INSTRUCTION) {
		signum = SIGILL;
		si_code = 1;
		insn_length = fault_offset > 0 ? fault_offset : 0;
	}
	else if (code == EXCEPTION_BREAKPOINT || code == EXCEPTION_SINGLE_STEP) {
		signum = SIGTRAP;
		si_code = 1;
		insn_length = fault_offset > 0 ? fault_offset : 1;
	}
	else if (code == EXCEPTION_DATATYPE_MISALIGNMENT) {
		signum = SIGBUS;
		si_code = 1;
		addr = (uint32_t)(uintptr_t)pExceptionInfo->ExceptionRecord->ExceptionAddress;
		insn_length = fault_offset > 0 ? fault_offset : 0;
	}
	else {
		signum = SIGFPE;
		si_code = 1;
		insn_length = fault_offset > 0 ? fault_offset : 0;
	}

	result.valid = 1;
	result.length = insn_length;
	result.signum = signum;
	result.si_code = si_code;
	result.addr = addr;

	*pExceptionInfo->ContextRecord = fault_context;
	pExceptionInfo->ContextRecord->ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
#if ARCH_X64
	pExceptionInfo->ContextRecord->Rip = (uintptr_t)&resume;
#else
	pExceptionInfo->ContextRecord->Eip = (uintptr_t)&resume;
#endif

	return EXCEPTION_CONTINUE_EXECUTION;
}

void inject(void)
{
	int k;
	for (k = 1; k <= MAX_INSN_LENGTH; k++) {
		uint8_t* test_loc = guard_boundary - k;
		memcpy(test_loc, inj.i.bytes, k);

		execute_target(test_loc);

		if (result.signum == SIGSEGV && last_fault_addr == (uintptr_t)guard_boundary) {
			continue;
		}

		result.length = k;
		return;
	}

	result.length = MAX_INSN_LENGTH;
}

void get_rand_insn_in_range(range_t* r)
{
	static uint8_t inclusive_end[MAX_INSN_LENGTH];
	int i;
	bool all_max = true;
	bool all_min = true;

	memcpy(inclusive_end, &r->end.bytes, MAX_INSN_LENGTH);
	i = MAX_INSN_LENGTH - 1;
	while (i >= 0) {
		inclusive_end[i]--;
		if (inclusive_end[i] != 0xff) {
			break;
		}
		i--;
	}

	for (i = 0; i < MAX_INSN_LENGTH; i++) {
		if (all_max && all_min) {
			inj.i.bytes[i] = rand() % (inclusive_end[i] - r->start.bytes[i] + 1) + r->start.bytes[i];
		}
		else if (all_max) {
			inj.i.bytes[i] = rand() % (inclusive_end[i] + 1);
		}
		else if (all_min) {
			inj.i.bytes[i] = rand() % (256 - r->start.bytes[i]) + r->start.bytes[i];
		}
		else {
			inj.i.bytes[i] = rand() % 256;
		}
		all_max = all_max && (inj.i.bytes[i] == inclusive_end[i]);
		all_min = all_min && (inj.i.bytes[i] == r->start.bytes[i]);
	}
}

void init_inj(const insn_t* new_insn)
{
	inj.i = *new_insn;
	inj.index = -1;
	inj.last_len = -1;
}

bool move_next_instruction(void)
{
	while (1) {
		int i;

		switch (mode) {
			case RAND:
				if (!search_range.started) {
					init_inj(&null_insn);
					get_rand_insn_in_range(&search_range);
				}
				else {
					get_rand_insn_in_range(&search_range);
				}
				break;
			case BRUTE:
				if (!search_range.started) {
					init_inj(&search_range.start);
					inj.index = config.brute_depth - 1;
				}
				else {
					for (inj.index = config.brute_depth - 1; inj.index >= 0; inj.index--) {
						inj.i.bytes[inj.index]++;
						if (inj.i.bytes[inj.index]) {
							break;
						}
					}
				}
				break;
			case TUNNEL:
				if (!search_range.started) {
					init_inj(&search_range.start);
					inj.index = search_range.start.len;
				}
				else {
					if (result.length != inj.last_len && inj.index < (int)result.length - 1) {
						inj.index = (int)result.length - 1;
					}
					inj.last_len = result.length;

					inj.i.bytes[inj.index]++;

					while (inj.index >= 0 && inj.i.bytes[inj.index] == 0) {
						inj.index--;
						if (inj.index >= 0) {
							inj.i.bytes[inj.index]++;
						}
						inj.last_len = -1;
					}
				}
				break;
			case DRIVEN:
				i = MAX_INSN_LENGTH;
				do {
					i -= (int)fread(inj.i.bytes, 1, i, stdin);
				} while (i > 0);
				break;
			default:
				assert(0);
		}
		search_range.started = true;

		if (is_backward_branch(inj.i.bytes)) {
			if (output == RAW) {
				result = (result_t){0,0,0,0,0};
				give_result(stdout);
			}
			continue;
		}

		if (is_indirect_branch(inj.i.bytes)) {
			if (output == RAW) {
				result = (result_t){0,0,0,0,0};
				give_result(stdout);
			}
			continue;
		}

		if (is_rip_relative_self_modify(inj.i.bytes)) {
			if (output == RAW) {
				result = (result_t){0,0,0,0,0};
				give_result(stdout);
			}
			continue;
		}

		if (modifies_sp(inj.i.bytes)) {
			if (output == RAW) {
				result = (result_t){0,0,0,0,0};
				give_result(stdout);
			}
			continue;
		}

		bool blacklisted = false;
		i = 0;
		while (opcode_blacklist[i].opcode) {
			if (has_opcode(opcode_blacklist[i].opcode, opcode_blacklist[i].len)) {
				if (output == RAW) {
					result = (result_t){0,0,0,0,0};
					give_result(stdout);
				}
				blacklisted = true;
				break;
			}
			i++;
		}
		if (blacklisted) continue;

		i = 0;
		while (prefix_blacklist[i].prefix) {
			if (has_prefix((uint8_t*)prefix_blacklist[i].prefix)) {
				if (output == RAW) {
					result = (result_t){0,0,0,0,0};
					give_result(stdout);
				}
				blacklisted = true;
				break;
			}
			i++;
		}
		if (blacklisted) continue;

		if (prefix_count() > config.max_prefix || (!config.allow_dup_prefix && has_dup_prefix())) {
			if (output == RAW) {
				result = (result_t){0,0,0,0,0};
				give_result(stdout);
			}
			continue;
		}

		if (memcmp(inj.i.bytes, search_range.end.bytes, sizeof(inj.i.bytes)) >= 0) {
			return false;
		}

		switch (mode) {
			case RAND:
				return true;
			case BRUTE:
				return inj.index >= 0;
			case TUNNEL:
				return inj.index >= 0;
			case DRIVEN:
				return true;
			default:
				assert(0);
		}
	}
}

void give_result(FILE* f)
{
	switch (output) {
		case TEXT:
			switch (mode) {
				case BRUTE:
				case TUNNEL:
				case RAND:
				case DRIVEN:
					sync_fprintf(f, " %s", expected_length == (int)result.length ? " " : ".");
					sync_fprintf(f, "r: (%2d) ", result.length);
					if (result.signum == SIGILL)  { sync_fprintf(f, "sigill "); }
					if (result.signum == SIGSEGV) { sync_fprintf(f, "sigsegv"); }
					if (result.signum == SIGFPE)  { sync_fprintf(f, "sigfpe "); }
					if (result.signum == SIGBUS)  { sync_fprintf(f, "sigbus "); }
					if (result.signum == SIGTRAP) { sync_fprintf(f, "sigtrap"); }
					sync_fprintf(f, " %3d ", result.si_code);
					sync_fprintf(f, " %08x ", result.addr);
					print_mc(f, result.length);
					sync_fprintf(f, "\n");
					break;
				default:
					assert(0);
			}
			break;
		case RAW:
#if USE_CAPSTONE
			{
				uint8_t* code = inj.i.bytes;
				size_t code_size = MAX_INSN_LENGTH;
				uint64_t address = (uintptr_t)packet;
			
				if (cs_disasm_iter(capstone_handle, (const uint8_t**)&code, &code_size, &address, capstone_insn)) {
#if RAW_REPORT_DISAS_LEN
					disas.len = (int)(address - (uintptr_t)packet);
#endif
#if RAW_REPORT_DISAS_VAL
					disas.val = true;
#endif
				}
				else {
#if RAW_REPORT_DISAS_LEN
					disas.len = (int)(address - (uintptr_t)packet);
#endif
#if RAW_REPORT_DISAS_VAL
					disas.val = false;
#endif
				}
#if RAW_REPORT_DISAS_MNE || RAW_REPORT_DISAS_OPS || RAW_REPORT_DISAS_LEN
				sync_fwrite(&disas, sizeof(disas), 1, stdout);
#endif
			}
#endif
			sync_fwrite(inj.i.bytes, RAW_REPORT_INSN_BYTES, 1, stdout);
			sync_fwrite(&result, sizeof(result), 1, stdout);
			break;
		default:
			assert(0);
	}
	sync_fflush(stdout, false);
}

void init_config(int argc, char** argv)
{
	int c, i;
	opterr = 0;
	bool seed_given = false;
	while ((c = getopt(argc, argv, "?brtdRTx0Ns:DB:P:S:i:e:c:X:j:l:")) != -1) {
		switch (c) {
			case 'b': mode = BRUTE; break;
			case 'r': mode = RAND; break;
			case 't': mode = TUNNEL; break;
			case 'd': mode = DRIVEN; break;
			case 'R': output = RAW; break;
			case 'T': output = TEXT; break;
			case 'x': config.show_tick = true; break;
			case '0': config.enable_null_access = true; break;
			case 'N': config.nx_support = false; break;
			case 's': sscanf(optarg, "%ld", &config.seed); seed_given = true; break;
			case 'P': sscanf(optarg, "%d", &config.max_prefix); break;
			case 'B': sscanf(optarg, "%d", &config.brute_depth); break;
			case 'D': config.allow_dup_prefix = true; break;
			case 'i':
				i = 0;
				while (optarg[i * 2] && optarg[i * 2 + 1] && i < MAX_INSN_LENGTH) {
					unsigned int k;
					sscanf(optarg + i * 2, "%02x", &k);
					total_range.start.bytes[i] = k;
					i++;
				}
				total_range.start.len = i;
				break;
			case 'e':
				i = 0;
				while (optarg[i * 2] && optarg[i * 2 + 1] && i < MAX_INSN_LENGTH) {
					unsigned int k;
					sscanf(optarg + i * 2, "%02x", &k);
					total_range.end.bytes[i] = k;
					i++;
				}
				total_range.end.len = i;
				break;
			case 'c': config.force_core = true; sscanf(optarg, "%d", &config.core); break;
			case 'j': sscanf(optarg, "%d", &config.jobs); break;
			case 'l': sscanf(optarg, "%d", &config.range_bytes); break;
			default: break;
		}
	}
	if (!seed_given) config.seed = (long)time(0);
}

void pin_core(void)
{
	if (config.force_core) {
		DWORD_PTR mask = ((DWORD_PTR)1) << config.core;
		SetProcessAffinityMask(GetCurrentProcess(), mask);
	}
}

void tick(void)
{
	static uint64_t t = 0;
	if (config.show_tick) {
		t++;
		if ((t & TICK_MASK) == 0) {
			sync_fprintf(stderr, "t: ");
			print_mc(stderr, 8);
			sync_fprintf(stderr, "... ");
			#if USE_CAPSTONE
			print_asm(stderr);
			sync_fprintf(stderr, "\t");
			#endif
			give_result(stderr);
			sync_fflush(stderr, false);
		}
	}
}

void pretext(void)
{
	if (output == TEXT) {
		sync_fprintf(stdout, "r: ");
		print_mc(stdout, 8);
		sync_fprintf(stdout, "... ");
		#if USE_CAPSTONE
		print_asm(stdout);
		sync_fprintf(stdout, " ");
		#endif
		sync_fflush(stdout, false);
	}
}

int main(int argc, char** argv)
{
	SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);

	_setmode(_fileno(stdout), _O_BINARY);
	_setmode(_fileno(stderr), _O_BINARY);

	pool_mutex = CreateMutexA(NULL, FALSE, NULL);
	output_mutex = CreateMutexA(NULL, FALSE, NULL);

	init_config(argc, argv);
	pin_core();
	srand(config.seed);

	arena_buffer = VirtualAlloc(NULL, ARENA_SIZE, MEM_RESERVE, PAGE_NOACCESS);
	assert(arena_buffer != NULL);

	void* page0 = VirtualAlloc(arena_buffer, PAGE_SIZE, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	assert(page0 != NULL);

	void* page1 = VirtualAlloc((uint8_t*)arena_buffer + PAGE_SIZE, PAGE_SIZE, MEM_COMMIT, PAGE_NOACCESS);
	assert(page1 != NULL);

	packet = (char*)page0;
	guard_boundary = ((uint8_t*)arena_buffer) + PAGE_SIZE;

#if USE_CAPSTONE
	if (cs_open(CS_ARCH_X86, CS_MODE, &capstone_handle) != CS_ERR_OK) exit(1);
	cs_option(capstone_handle, CS_OPT_DETAIL, CS_OPT_ON);
	capstone_insn = cs_malloc(capstone_handle);
#endif

	AddVectoredExceptionHandler(1, veh_handler);
	initialize_ranges();

	while (move_next_range()) {
		while (move_next_instruction()) {
			pretext();

			int branch_len = 0;
			if (is_branch_insn(inj.i.bytes, &branch_len)) {
				expected_length = branch_len;
			}
			else {
				expected_length = 0;
#if USE_CAPSTONE
				uint8_t* code = inj.i.bytes;
				size_t code_size = MAX_INSN_LENGTH;
				uint64_t address = (uintptr_t)packet;
				if (cs_disasm_iter(capstone_handle, (const uint8_t**)&code, &code_size, &address, capstone_insn)) {
					expected_length = (int)(address - (uintptr_t)packet);
				}
#endif
			}

			inject();

			if (is_branch_insn(inj.i.bytes, NULL)) {
				result.length = expected_length;
			}

			give_result(stdout);
			tick();
		}
	}

	sync_fflush(stdout, true);
	sync_fflush(stderr, true);

#if USE_CAPSTONE
	cs_free(capstone_insn, 1);
	cs_close(&capstone_handle);
#endif

	VirtualFree(arena_buffer, 0, MEM_RELEASE);
	free_ranges();
	CloseHandle(pool_mutex);
	CloseHandle(output_mutex);

	return 0;
}
