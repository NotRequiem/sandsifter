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
	#if __has_include(<capstone/capstone.h>)
		#include <capstone/capstone.h>
	#else
		#include "capstone.h"
	#endif
	csh capstone_handle;
	cs_insn *capstone_insn;
#endif

#define SIGILL  4
#define SIGTRAP 5
#define SIGBUS  7
#define SIGFPE  8
#define SIGSEGV 11

#define MAX_INSN_LENGTH 15
#define TICK_MASK 0xffff
#define RAW_REPORT_INSN_BYTES 16
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
};

search_mode_t mode = TUNNEL;
output_t output = TEXT;

static uint8_t* exec_pages = NULL;
static uint8_t* page_boundary = NULL;
static uint8_t dummy_stack_area[65536] __attribute__ ((aligned(4096)));
static uint8_t scratch_area[65536] __attribute__ ((aligned(4096)));

typedef struct {
	uint8_t bytes[RAW_REPORT_INSN_BYTES];
	int len;
} insn_t;

typedef struct {
	insn_t i;
	int index;
	int last_len;
} inj_t;
inj_t inj;

static const insn_t null_insn = {0};
static uintptr_t saved_host_sp = 0;
static void* target_jump_addr = NULL;
static volatile bool in_target = false;
static volatile bool last_fault_was_fetch = false;
static int expected_length = 0;

#pragma pack(push, 1)
typedef struct {
	uint32_t valid;
	uint32_t length;
	uint32_t signum;
	uint32_t si_code;
#if ARCH_X64
	uint64_t addr;
#else
	uint32_t addr;
#endif
} result_t;

typedef struct {
#if RAW_REPORT_DISAS_LEN
	int len;
#endif
#if RAW_REPORT_DISAS_VAL
	int val;
#endif
} disas_t;

typedef struct {
	disas_t disas;
	uint8_t raw_insn[RAW_REPORT_INSN_BYTES];
	result_t result;
} report_t;
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
	{ (uint8_t*)"\xcd\x2c",     2, "assert" },
	{ (uint8_t*)"\xcd\x2d",     2, "debug service" },
	{ (uint8_t*)"\xcd\x2e",     2, "legacy syscall" },
	{ (uint8_t*)"\xcc",         1, "int3" },
	{ (uint8_t*)"\xce",         1, "into" },
	{ (uint8_t*)"\xf1",         1, "icebp" },
	{ (uint8_t*)"\xc8",         1, "enter" },
	{ (uint8_t*)"\xc7\xf8",     2, "xbegin" },
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
	.start = {.bytes = {0}, .len = 0},
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

bool is_prefix(uint8_t x);
bool has_opcode(const uint8_t* op, int op_len);
bool is_backward_branch(const uint8_t* b);
bool is_indirect_branch(const uint8_t* b);
bool is_rip_relative_self_modify(const uint8_t* b);
bool modifies_sp(const uint8_t* b);
void print_mc(FILE* f, int length);
void give_result(FILE* f);
int prefix_count(void);
bool has_dup_prefix(void);
void inject(void);
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
	(void)force;
	WaitForSingleObject(output_mutex, INFINITE);
	fflush(f);
	ReleaseMutex(output_mutex);
}

void zero_insn_end(insn_t* insn, int marker)
{
	for (int i = marker; i < MAX_INSN_LENGTH; i++) {
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
			if (i < 0) break;
			insn->bytes[i]++;
		}
	}

	insn->len = marker;
	return i >= 0;
}

void initialize_ranges(void)
{
	if (range_marker == NULL) {
		char map_name[128];
		snprintf(map_name, sizeof(map_name), "Local\\SandsifterRange_%ld", config.seed);
		hMapRange = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, sizeof(insn_t), map_name);
		if (hMapRange == NULL) {
			hMapRange = OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE, map_name);
		}
		assert(hMapRange != NULL);
		bool first_init = (GetLastError() != ERROR_ALREADY_EXISTS);
		range_marker = (insn_t*)MapViewOfFile(hMapRange, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(insn_t));
		assert(range_marker != NULL);
		if (first_init) {
			*range_marker = total_range.start;
		}
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
int update_disas(void)
{
	uint8_t* code = inj.i.bytes;
	size_t code_size = MAX_INSN_LENGTH;
	uint64_t address = 0;

	if (cs_disasm_iter(capstone_handle, (const uint8_t**)&code, &code_size, &address, capstone_insn)) {
		expected_length = capstone_insn[0].size;
		disas.len = expected_length;
		disas.val = 1;
	}
	else {
		expected_length = 0;
		disas.len = 0;
		disas.val = 0;
	}
	return expected_length;
}

int print_asm(FILE* f)
{
	if (output == TEXT) {
		if (disas.val) {
			sync_fprintf(f, "%10s %-45s (%2d)", capstone_insn[0].mnemonic, capstone_insn[0].op_str, disas.len);
		}
		else {
			sync_fprintf(f, "%10s %-45s (%2d)", "(unk)", " ", 0);
		}
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

bool is_backward_branch(const uint8_t* b)
{
	int idx = 0;
	while (idx < MAX_INSN_LENGTH && is_prefix(b[idx])) idx++;
	if (idx >= MAX_INSN_LENGTH) return false;

	uint8_t op = b[idx];

	if ((op >= 0x70 && op <= 0x7f) || op == 0xeb || (op >= 0xe0 && op <= 0xe3)) {
		if (idx + 1 < MAX_INSN_LENGTH) {
			int8_t disp8 = (int8_t)b[idx + 1];
			if (disp8 <= 0) return true;
		}
	}

	if (op == 0x0f && idx + 1 < MAX_INSN_LENGTH) {
		uint8_t op2 = b[idx + 1];
		if (op2 >= 0x80 && op2 <= 0x8f) {
			if (idx + 5 < MAX_INSN_LENGTH) {
				int32_t disp32 = (int32_t)(b[idx + 2] | (b[idx + 3] << 8) | 
				                          (b[idx + 4] << 16) | (b[idx + 5] << 24));
				if (disp32 <= 0) return true;
			}
		}
	}

	if (op == 0xe9 && idx + 4 < MAX_INSN_LENGTH) {
		int32_t disp32 = (int32_t)(b[idx + 1] | (b[idx + 2] << 8) | 
		                          (b[idx + 3] << 16) | (b[idx + 4] << 24));
		if (disp32 <= 0) return true;
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
		if (reg >= 2 && reg <= 5) return true;
	}

	if (op == 0xea || op == 0x9a) return true;

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
				if (disp32 >= -64 && disp32 <= 64) return true;
			}
		}
	}
#endif
	return false;
}

bool modifies_sp(const uint8_t* b)
{
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
	for (int i = 0; i < MAX_INSN_LENGTH; i++) {
		if (!is_prefix(inj.i.bytes[i])) return i;
	}
	return MAX_INSN_LENGTH;
}

bool has_dup_prefix(void)
{
	int byte_count[256] = {0};
	for (int i = 0; i < MAX_INSN_LENGTH; i++) {
		if (is_prefix(inj.i.bytes[i])) {
			byte_count[inj.i.bytes[i]]++;
		}
		else {
			break;
		}
	}
	for (int i = 0; i < 256; i++) {
		if (byte_count[i] > 1) return true;
	}
	return false;
}

bool has_opcode(const uint8_t* op, int op_len)
{
	int i = 0;
	while (i < MAX_INSN_LENGTH && is_prefix(inj.i.bytes[i])) {
		i++;
	}
	if (i + op_len > MAX_INSN_LENGTH) return false;
	return memcmp(&inj.i.bytes[i], op, op_len) == 0;
}

bool has_prefix(uint8_t* pre)
{
	for (int i = 0; i < MAX_INSN_LENGTH; i++) {
		if (is_prefix(inj.i.bytes[i])) {
			int j = 0;
			do {
				if (inj.i.bytes[i] == pre[j]) return true;
				j++;
			} while (pre[j]);
		}
		else {
			return false;
		}
	}
	return false;
}

__attribute__((noinline)) void execute_target(void* addr)
{
	target_jump_addr = addr;

	uintptr_t safe_target = (uintptr_t)(scratch_area + 32768);
	uintptr_t* stk = (uintptr_t*)dummy_stack_area;
	for (size_t s = 0; s < sizeof(dummy_stack_area) / sizeof(uintptr_t); s++) {
		stk[s] = (uintptr_t)safe_target;
	}

	__asm__ __volatile__ ("cld\n\t");
	__asm__ __volatile__ ("emms\n\t");
	__asm__ __volatile__ ("fninit\n\t");
	uint32_t default_mxcsr = 0x1f80;
	__asm__ __volatile__ ("ldmxcsr %0" : : "m"(default_mxcsr));

	in_target = true;

#if ARCH_X64
	__asm__ __volatile__ (
		"pushq %%rbx \n\t"
		"pushq %%rbp \n\t"
		"pushq %%rdi \n\t"
		"pushq %%rsi \n\t"
		"pushq %%r12 \n\t"
		"pushq %%r13 \n\t"
		"pushq %%r14 \n\t"
		"pushq %%r15 \n\t"
		"subq $160, %%rsp \n\t"
		"movdqu %%xmm6, 0(%%rsp) \n\t"
		"movdqu %%xmm7, 16(%%rsp) \n\t"
		"movdqu %%xmm8, 32(%%rsp) \n\t"
		"movdqu %%xmm9, 48(%%rsp) \n\t"
		"movdqu %%xmm10, 64(%%rsp) \n\t"
		"movdqu %%xmm11, 80(%%rsp) \n\t"
		"movdqu %%xmm12, 96(%%rsp) \n\t"
		"movdqu %%xmm13, 112(%%rsp) \n\t"
		"movdqu %%xmm14, 128(%%rsp) \n\t"
		"movdqu %%xmm15, 144(%%rsp) \n\t"
		"movq %%rsp, %0 \n\t"
		"leaq dummy_stack_area+32760(%%rip), %%rsp \n\t"
		"movq %1, %%rax \n\t"
		"movq %1, %%rbx \n\t"
		"movq %1, %%rcx \n\t"
		"movq %1, %%rdx \n\t"
		"movq %1, %%rsi \n\t"
		"movq %1, %%rdi \n\t"
		"movq %1, %%rbp \n\t"
		"movq %1, %%r8  \n\t"
		"movq %1, %%r9  \n\t"
		"movq %1, %%r12 \n\t"
		"movq %1, %%r13 \n\t"
		"movq %1, %%r14 \n\t"
		"movq %1, %%r15 \n\t"
		"movq %%rsp, %%r10 \n\t"
		"subq $8, %%r10 \n\t"
		"movq %%ss, %%r11 \n\t"
		"pushq %%r11 \n\t"
		"pushq %%r10 \n\t"
		"pushfq \n\t"
		"orq $0x100, (%%rsp) \n\t"
		"movq %%cs, %%r11 \n\t"
		"pushq %%r11 \n\t"
		"pushq %2 \n\t"
		"movq %%rax, %%r10 \n\t"
		"movq %%rax, %%r11 \n\t"
		"iretq \n\t"
		".globl resume \n\t"
		"resume: \n\t"
		"cld \n\t"
		"movq %0, %%rsp \n\t"
		"movdqu 0(%%rsp), %%xmm6 \n\t"
		"movdqu 16(%%rsp), %%xmm7 \n\t"
		"movdqu 32(%%rsp), %%xmm8 \n\t"
		"movdqu 48(%%rsp), %%xmm9 \n\t"
		"movdqu 64(%%rsp), %%xmm10 \n\t"
		"movdqu 80(%%rsp), %%xmm11 \n\t"
		"movdqu 96(%%rsp), %%xmm12 \n\t"
		"movdqu 112(%%rsp), %%xmm13 \n\t"
		"movdqu 128(%%rsp), %%xmm14 \n\t"
		"movdqu 144(%%rsp), %%xmm15 \n\t"
		"addq $160, %%rsp \n\t"
		"popq %%r15 \n\t"
		"popq %%r14 \n\t"
		"popq %%r13 \n\t"
		"popq %%r12 \n\t"
		"popq %%rsi \n\t"
		"popq %%rdi \n\t"
		"popq %%rbp \n\t"
		"popq %%rbx \n\t"
		"emms \n\t"
		"fninit \n\t"
		"cld \n\t"
		: "=m"(saved_host_sp)
		: "r"(safe_target), "r"(target_jump_addr)
		: "rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11",
		  "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "memory"
	);
#else
	__asm__ __volatile__ (
		"pushl %%ebx \n\t"
		"pushl %%esi \n\t"
		"pushl %%edi \n\t"
		"pushl %%ebp \n\t"
		"movl %%esp, %0 \n\t"
		"leal dummy_stack_area+32764, %%esp \n\t"
		"movl %1, %%eax \n\t"
		"movl %1, %%ebx \n\t"
		"movl %1, %%ecx \n\t"
		"movl %1, %%esi \n\t"
		"movl %1, %%edi \n\t"
		"movl %1, %%ebp \n\t"
		"pushfl \n\t"
		"orl $0x100, (%%esp) \n\t"
		"movl %%cs, %%edx \n\t"
		"pushl %%edx \n\t"
		"pushl %2 \n\t"
		"movl %%eax, %%edx \n\t"
		"iretd \n\t"
		".globl resume \n\t"
		"resume: \n\t"
		"cld \n\t"
		"movl %0, %%esp \n\t"
		"popl %%ebp \n\t"
		"popl %%edi \n\t"
		"popl %%esi \n\t"
		"popl %%ebx \n\t"
		"emms \n\t"
		"fninit \n\t"
		"cld \n\t"
		: "=m"(saved_host_sp)
		: "r"(safe_target), "r"(target_jump_addr)
		: "eax", "ecx", "edx", "memory"
	);
#endif

	in_target = false;
}

LONG WINAPI veh_handler(PEXCEPTION_POINTERS pExceptionInfo)
{
	if (!in_target) {
		return EXCEPTION_CONTINUE_SEARCH;
	}

	__asm__ __volatile__ ("cld\n\t");
	__asm__ __volatile__ ("emms\n\t");
	__asm__ __volatile__ ("fninit\n\t");
	uint32_t default_mxcsr = 0x1f80;
	__asm__ __volatile__ ("ldmxcsr %0" : : "m"(default_mxcsr));

#if ARCH_X64
	uintptr_t fault_ip = (uintptr_t)pExceptionInfo->ContextRecord->Rip;
#else
	uintptr_t fault_ip = (uintptr_t)pExceptionInfo->ContextRecord->Eip;
#endif

	DWORD code = pExceptionInfo->ExceptionRecord->ExceptionCode;
	uintptr_t fault_addr = 0;
	uint32_t access_type = 0;

	if (pExceptionInfo->ExceptionRecord->NumberParameters > 0) {
		access_type = (uint32_t)pExceptionInfo->ExceptionRecord->ExceptionInformation[0];
	}
	if (pExceptionInfo->ExceptionRecord->NumberParameters > 1) {
		fault_addr = (uintptr_t)pExceptionInfo->ExceptionRecord->ExceptionInformation[1];
	}

	if (code == EXCEPTION_ACCESS_VIOLATION && 
	    (access_type == 8 || (fault_addr >= (uintptr_t)page_boundary && fault_addr < (uintptr_t)(page_boundary + 4096)))) {
		last_fault_was_fetch = true;
	}
	else {
		last_fault_was_fetch = false;

		uint32_t signum = 0;
		uint32_t si_code = 0;
		uintptr_t addr = 0;

		if (code == EXCEPTION_SINGLE_STEP) {
			signum = SIGTRAP;
			si_code = 1;
			addr = 0;
		}
		else if (code == EXCEPTION_BREAKPOINT) {
			signum = SIGTRAP;
			si_code = 1;
			addr = fault_ip;
		}
		else if (code == EXCEPTION_ILLEGAL_INSTRUCTION) {
			signum = SIGILL;
			si_code = 1;
			addr = fault_ip;
		}
		else if (code == EXCEPTION_PRIV_INSTRUCTION) {
			signum = SIGSEGV;
			si_code = 1;
			addr = fault_ip;
		}
		else if (code == EXCEPTION_ACCESS_VIOLATION || code == EXCEPTION_IN_PAGE_ERROR) {
			signum = SIGSEGV;
			si_code = access_type;
			addr = fault_addr;
		}
		else if (code == EXCEPTION_GUARD_PAGE || code == EXCEPTION_STACK_OVERFLOW) {
			signum = SIGSEGV;
			si_code = 1;
			addr = fault_addr;
		}
		else if (code == EXCEPTION_DATATYPE_MISALIGNMENT || code == EXCEPTION_ARRAY_BOUNDS_EXCEEDED) {
			signum = SIGBUS;
			si_code = 1;
			addr = fault_addr;
		}
		else if (code == EXCEPTION_INT_DIVIDE_BY_ZERO ||
		         code == EXCEPTION_INT_OVERFLOW ||
		         code == EXCEPTION_FLT_DENORMAL_OPERAND ||
		         code == EXCEPTION_FLT_DIVIDE_BY_ZERO ||
		         code == EXCEPTION_FLT_INEXACT_RESULT ||
		         code == EXCEPTION_FLT_INVALID_OPERATION ||
		         code == EXCEPTION_FLT_OVERFLOW ||
		         code == EXCEPTION_FLT_STACK_CHECK ||
		         code == EXCEPTION_FLT_UNDERFLOW ||
		         code == ERROR_FLOAT_MULTIPLE_TRAPS) {
			signum = SIGFPE;
			si_code = 1;
			addr = fault_ip;
		}
		else {
			signum = SIGILL;
			si_code = 1;
			addr = fault_ip;
		}

		result.valid = 1;
		result.signum = signum;
		result.si_code = si_code;
		result.addr = addr;
	}

	pExceptionInfo->ContextRecord->EFlags &= ~0x0100;

#if ARCH_X64
	pExceptionInfo->ContextRecord->Rip = (uintptr_t)&resume;
	pExceptionInfo->ContextRecord->Rsp = saved_host_sp;
#else
	pExceptionInfo->ContextRecord->Eip = (uintptr_t)&resume;
	pExceptionInfo->ContextRecord->Esp = saved_host_sp;
#endif

	return EXCEPTION_CONTINUE_EXECUTION;
}

void inject(void)
{
	result.valid = 0;
	result.length = 0;
	result.signum = 0;
	result.si_code = 0;
	result.addr = 0;

	for (int k = 1; k <= MAX_INSN_LENGTH; k++) {
		uint8_t* target = page_boundary - k;
		memcpy(target, inj.i.bytes, k);

		last_fault_was_fetch = false;
		execute_target(target);

		if (last_fault_was_fetch) {
			continue;
		}

		result.length = k;
		break;
	}

	if (result.length == 0) {
		result.length = MAX_INSN_LENGTH;
	}
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
		if (inclusive_end[i] != 0xff) break;
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
				}
				get_rand_insn_in_range(&search_range);
				break;
			case BRUTE:
				if (!search_range.started) {
					init_inj(&search_range.start);
					inj.index = config.brute_depth - 1;
				}
				else {
					for (inj.index = config.brute_depth - 1; inj.index >= 0; inj.index--) {
						inj.i.bytes[inj.index]++;
						if (inj.i.bytes[inj.index]) break;
					}
				}
				break;
			case TUNNEL:
				if (!search_range.started) {
					init_inj(&search_range.start);
					inj.index = search_range.start.len;
				}
				else {
					int eff_len = result.length > 0 ? (int)result.length : (expected_length > 0 ? expected_length : 1);
					if (eff_len != inj.last_len && inj.index < eff_len - 1) {
						inj.index = eff_len - 1;
					}
					inj.last_len = eff_len;

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

		if (is_backward_branch(inj.i.bytes)) continue;
		if (is_indirect_branch(inj.i.bytes)) continue;
		if (is_rip_relative_self_modify(inj.i.bytes)) continue;
		if (modifies_sp(inj.i.bytes)) continue;

		bool blacklisted = false;
		i = 0;
		while (opcode_blacklist[i].opcode) {
			if (has_opcode(opcode_blacklist[i].opcode, opcode_blacklist[i].len)) {
				blacklisted = true;
				break;
			}
			i++;
		}
		if (blacklisted) continue;

		i = 0;
		while (prefix_blacklist[i].prefix) {
			if (has_prefix((uint8_t*)prefix_blacklist[i].prefix)) {
				blacklisted = true;
				break;
			}
			i++;
		}
		if (blacklisted) continue;

		if (prefix_count() > config.max_prefix || (!config.allow_dup_prefix && has_dup_prefix())) {
			continue;
		}

		if (memcmp(inj.i.bytes, search_range.end.bytes, sizeof(inj.i.bytes)) >= 0) {
			return false;
		}

		switch (mode) {
			case RAND:   return true;
			case BRUTE:  return inj.index >= 0;
			case TUNNEL: return inj.index >= 0;
			case DRIVEN: return true;
			default:     assert(0);
		}
	}
}

void give_result(FILE* f)
{
	switch (output) {
		case TEXT:
			sync_fprintf(f, " %s", expected_length == (int)result.length ? " " : ".");
			sync_fprintf(f, "r: (%2d) ", result.length);
			if (result.signum == SIGILL)  { sync_fprintf(f, "sigill "); }
			if (result.signum == SIGSEGV) { sync_fprintf(f, "sigsegv"); }
			if (result.signum == SIGFPE)  { sync_fprintf(f, "sigfpe "); }
			if (result.signum == SIGBUS)  { sync_fprintf(f, "sigbus "); }
			if (result.signum == SIGTRAP) { sync_fprintf(f, "sigtrap"); }
			sync_fprintf(f, " %3d ", result.si_code);
#if ARCH_X64
			sync_fprintf(f, " %016llx ", (unsigned long long)result.addr);
#else
			sync_fprintf(f, " %08x ", result.addr);
#endif
			print_mc(f, result.length);
			sync_fprintf(f, "\n");
			break;
		case RAW:
			{
				report_t report = {0};
				report.disas = disas;
				memcpy(report.raw_insn, inj.i.bytes, RAW_REPORT_INSN_BYTES);
				report.result = result;
				sync_fwrite(&report, sizeof(report), 1, f);
			}
			break;
		default:
			assert(0);
	}
	sync_fflush(f, false);
}

void init_config(int argc, char** argv)
{
	int c, i;
	opterr = 0;
	bool seed_given = false;
	while ((c = getopt(argc, argv, "?brtdRTx0s:DB:P:S:i:e:c:X:j:l:")) != -1) {
		switch (c) {
			case 'b': mode = BRUTE; break;
			case 'r': mode = RAND; break;
			case 't': mode = TUNNEL; break;
			case 'd': mode = DRIVEN; break;
			case 'R': output = RAW; break;
			case 'T': output = TEXT; break;
			case 'x': config.show_tick = true; break;
			case '0': config.enable_null_access = true; break;
			case 's': sscanf(optarg, "%ld", &config.seed); seed_given = true; break;
			case 'P': sscanf(optarg, "%d", &config.max_prefix); break;
			case 'B': sscanf(optarg, "%d", &config.brute_depth); break;
			case 'D': config.allow_dup_prefix = true; break;
			case 'i':
				i = 0;
				while (optarg[i * 2] && optarg[i * 2 + 1] && i < MAX_INSN_LENGTH) {
					unsigned int k;
					sscanf(optarg + i * 2, "%02x", &k);
					total_range.start.bytes[i] = (uint8_t)k;
					i++;
				}
				total_range.start.len = i;
				break;
			case 'e':
				i = 0;
				while (optarg[i * 2] && optarg[i * 2 + 1] && i < MAX_INSN_LENGTH) {
					unsigned int k;
					sscanf(optarg + i * 2, "%02x", &k);
					total_range.end.bytes[i] = (uint8_t)k;
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
			if (output == TEXT) {
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

	init_config(argc, argv);
	pin_core();
	srand(config.seed);

	char mutex_pool_name[128];
	char mutex_out_name[128];
	snprintf(mutex_pool_name, sizeof(mutex_pool_name), "Local\\SandsifterPool_%ld", config.seed);
	snprintf(mutex_out_name, sizeof(mutex_out_name), "Local\\SandsifterOut_%ld", config.seed);
	pool_mutex = CreateMutexA(NULL, FALSE, mutex_pool_name);
	output_mutex = CreateMutexA(NULL, FALSE, mutex_out_name);

	if (config.enable_null_access) {
		VirtualAlloc((void*)1, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	}

	exec_pages = (uint8_t*)VirtualAlloc(NULL, 8192, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	assert(exec_pages != NULL);

	DWORD old_prot;
	VirtualProtect(exec_pages, 4096, PAGE_EXECUTE_READWRITE, &old_prot);
	VirtualProtect(exec_pages + 4096, 4096, PAGE_NOACCESS, &old_prot);
	page_boundary = exec_pages + 4096;

#if USE_CAPSTONE
	if (cs_open(CS_ARCH_X86, CS_MODE, &capstone_handle) != CS_ERR_OK) exit(1);
	cs_option(capstone_handle, CS_OPT_DETAIL, CS_OPT_ON);
	capstone_insn = cs_malloc(capstone_handle);
#endif

	AddVectoredExceptionHandler(1, veh_handler);
	initialize_ranges();

	while (move_next_range()) {
		while (move_next_instruction()) {
#if USE_CAPSTONE
			update_disas();
#endif
			pretext();
			inject();
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

	VirtualFree(exec_pages, 0, MEM_RELEASE);
	free_ranges();
	CloseHandle(pool_mutex);
	CloseHandle(output_mutex);

	return 0;
}
