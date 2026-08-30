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
#define TF        0x100
#define USE_TF    false

#define MAX_INSN_LENGTH 15
#define JMP_LENGTH 16

#define LINE_BUFFER_SIZE 256
#define BUFFER_LINES 16
#define SYNC_LINES_STDOUT BUFFER_LINES
#define SYNC_LINES_STDERR BUFFER_LINES

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

#if ARCH_X64
typedef struct {
	uint64_t rax;
	uint64_t rbx;
	uint64_t rcx;
	uint64_t rdx;
	uint64_t rsi;
	uint64_t rdi;
	uint64_t r8;
	uint64_t r9;
	uint64_t r10;
	uint64_t r11;
	uint64_t r12;
	uint64_t r13;
	uint64_t r14;
	uint64_t r15;
	uint64_t rbp;
	uint64_t rsp;
} state_t;
state_t inject_state = {0};
#else
typedef struct {
	uint32_t eax;
	uint32_t ebx;
	uint32_t ecx;
	uint32_t edx;
	uint32_t esi;
	uint32_t edi;
	uint32_t ebp;
	uint32_t esp;
} state_t;
state_t inject_state = {0};
#endif

void* packet_buffer = NULL;
char* packet = NULL;
static int current_insn_size = 0;

static uint8_t dummy_stack_area[65536] __attribute__ ((aligned(4096)));

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
	{ (uint8_t*)"\x0f\x34", 2, "sysenter" },
	{ (uint8_t*)"\x0f\x35", 2, "sysexit" },
	{ (uint8_t*)"\x0f\x05", 2, "syscall" },
	{ (uint8_t*)"\x0f\x07", 2, "sysret" },
	{ (uint8_t*)"\x0f\xa1", 2, "pop fs" },
	{ (uint8_t*)"\x0f\xa9", 2, "pop gs" },
	{ (uint8_t*)"\x0f\xa0", 2, "push fs" },
	{ (uint8_t*)"\x0f\xa8", 2, "push gs" },
	{ (uint8_t*)"\x0f\x01\xf8", 3, "swapgs" },
	{ (uint8_t*)"\x8e",     1, "mov seg" },
	{ (uint8_t*)"\xcd",     1, "int imm8" },
	{ (uint8_t*)"\xcc",     1, "int3" },
	{ (uint8_t*)"\xce",     1, "into" },
	{ (uint8_t*)"\xf1",     1, "icebp" },
	{ (uint8_t*)"\xc8",     1, "enter" },
#if !ARCH_X64
	{ (uint8_t*)"\xc5",     1, "lds" },
	{ (uint8_t*)"\xc4",     1, "les" },
#endif
	{ (uint8_t*)"\x0f\xb2", 2, "lss" },
	{ (uint8_t*)"\x0f\xb4", 2, "lfs" },
	{ (uint8_t*)"\x0f\xb5", 2, "lgs" },
#if ARCH_X64
	{ (uint8_t*)"\x63",     1, "movsxd" }, 
#endif
	{ (uint8_t*)"\xbc",     1, "mov sp" },
	{ (uint8_t*)"\xd1\xec", 2, "shr sp, 1" },
	{ (uint8_t*)"\xd1\xe4", 2, "shl sp, 1" },
	{ (uint8_t*)"\xd1\xfc", 2, "sar sp, 1" },
	{ (uint8_t*)"\xd1\xdc", 2, "rcr sp, 1" },
	{ (uint8_t*)"\xd1\xd4", 2, "rcl sp, 1" },
	{ (uint8_t*)"\xd1\xcc", 2, "ror sp, 1" },
	{ (uint8_t*)"\xd1\xc4", 2, "rol sp, 1" },
	{ (uint8_t*)"\x8d\xa2", 2, "lea sp" },
	{ (uint8_t*)"\xc7\xf8", 2, "xbegin" },
	{ (uint8_t*)"\x0f\xb9", 2, "ud2" },
	{ (uint8_t*)"\xc2",     1, "ret imm16" },
	{ (uint8_t*)"\xc3",     1, "ret" },
	{ (uint8_t*)"\xca",     1, "retf imm16" },
	{ (uint8_t*)"\xcb",     1, "retf" },
	{ (uint8_t*)"\xcf",     1, "iret" },
	{ (uint8_t*)"\x0f\x00", 2, "sldt/str/lldt/ltr" },
	{ (uint8_t*)"\x0f\x01", 2, "sgdt/sidt/lgdt/lidt/smsw/lmsw" },
	{ NULL, 0, NULL }
};

typedef struct {
	char* prefix;
	char* reason;
} ignore_pre_t;

ignore_pre_t prefix_blacklist[] = {
#if !ARCH_X64
	{ "\x65", "gs" },
#endif
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

char stdout_buffer[LINE_BUFFER_SIZE * BUFFER_LINES];
char* stdout_buffer_pos = stdout_buffer;
int stdout_sync_counter = 0;
char stderr_buffer[LINE_BUFFER_SIZE * BUFFER_LINES];
char* stderr_buffer_pos = stderr_buffer;
int stderr_sync_counter = 0;

static char* optarg = NULL;
static int optind = 1;
static int opterr = 1;
static int optopt = '?';

extern char resume;
static int expected_length;

bool is_prefix(uint8_t x);
bool has_opcode(const uint8_t* op, int op_len);
bool has_prefix(uint8_t* pre);
bool modifies_sp(const uint8_t* b);
bool is_backward_branch(const uint8_t* b);
bool is_rip_relative_write(const uint8_t* b);
void print_mc(FILE* f, int length);
void give_result(FILE* f);
int prefix_count(void);
bool has_dup_prefix(void);
void inject(int insn_size);
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

	if (f == stdout) {
		stdout_buffer_pos += vsprintf(stdout_buffer_pos, format, args);
	}
	else if (f == stderr) {
		stderr_buffer_pos += vsprintf(stderr_buffer_pos, format, args);
	}
	else {
		assert(0);
	}

	va_end(args);
}

void sync_fwrite(const void* ptr, size_t size, size_t count, FILE* f)
{
	if (f == stdout) {
		memcpy(stdout_buffer_pos, ptr, size * count);
		stdout_buffer_pos += size * count;
	}
	else if (f == stderr) {
		memcpy(stderr_buffer_pos, ptr, size * count);
		stderr_buffer_pos += size * count;
	}
	else {
		assert(0);
	}
}

void sync_fflush(FILE* f, bool force)
{
	if (f == stdout) {
		stdout_sync_counter++;
		if (stdout_sync_counter >= SYNC_LINES_STDOUT || force) {
			stdout_sync_counter = 0;
			WaitForSingleObject(output_mutex, INFINITE);
			fwrite(stdout_buffer, stdout_buffer_pos - stdout_buffer, 1, f);
			fflush(f);
			ReleaseMutex(output_mutex);
			stdout_buffer_pos = stdout_buffer;
		}
	}
	else if (f == stderr) {
		stderr_sync_counter++;
		if (stderr_sync_counter >= SYNC_LINES_STDERR || force) {
			stderr_sync_counter = 0;
			WaitForSingleObject(output_mutex, INFINITE);
			fwrite(stderr_buffer, stderr_buffer_pos - stderr_buffer, 1, f);
			fflush(f);
			ReleaseMutex(output_mutex);
			stderr_buffer_pos = stderr_buffer;
		}
	}
	else {
		assert(0);
	}
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

void print_insn(FILE* f, insn_t* insn)
{
	int i;
	for (i = 0; i < sizeof(insn->bytes); i++) {
		sync_fprintf(f, "%02x", insn->bytes[i]);
	}
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
		uint64_t address = (uintptr_t)packet_buffer;
	
		if (cs_disasm_iter(capstone_handle, (const uint8_t**)&code, &code_size, &address, capstone_insn)) {
			sync_fprintf(f, "%10s %-45s (%2d)", capstone_insn[0].mnemonic, capstone_insn[0].op_str, (int)(address - (uintptr_t)packet_buffer));
		}
		else {
			sync_fprintf(f, "%10s %-45s (%2d)", "(unk)", " ", (int)(address - (uintptr_t)packet_buffer));
		}
		expected_length = (int)(address - (uintptr_t)packet_buffer);
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

bool is_rip_relative_write(const uint8_t* b)
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
		if (op2 == 0x38 || op2 == 0x3a) {
			modrm_idx = idx + 3;
		} else {
			modrm_idx = idx + 2;
		}
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
			uint8_t base_op = op & ~1;
			if (base_op == 0x00 || base_op == 0x08 || base_op == 0x10 || base_op == 0x18 ||
			    base_op == 0x20 || base_op == 0x28 || base_op == 0x30 || base_op == 0x38 ||
			    base_op == 0x88 || base_op == 0xc0 || base_op == 0xc6 ||
			    (op >= 0xd0 && op <= 0xd3) || base_op == 0xf6 || base_op == 0xfe ||
			    op == 0x86 || op == 0x87) {
				return true;
			}
		}
	}
#endif
	return false;
}

bool modifies_sp(const uint8_t* b)
{
#if USE_CAPSTONE
	uint8_t* c_code = (uint8_t*)b;
	size_t c_size = MAX_INSN_LENGTH;
	uint64_t c_addr = 0x1000;
	if (cs_disasm_iter(capstone_handle, (const uint8_t**)&c_code, &c_size, &c_addr, capstone_insn)) {
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
		if (op2 == 0x05 || op2 == 0x07 || op2 == 0x34 || op2 == 0x35 || 
		    op2 == 0xa0 || op2 == 0xa1 || op2 == 0xa8 || op2 == 0xa9) return true;
		
		if (op2 == 0x38 || op2 == 0x3a) {
			modrm_idx = idx + 3;
		} else {
			modrm_idx = idx + 2;
		}
	} 
	else if (op == 0xc5) {
		modrm_idx = idx + 2;
	} 
	else if (op == 0xc4 || op == 0x8f || op == 0x62) {
		modrm_idx = idx + 3;
	} 
	else {
		modrm_idx = idx + 1;
	}

	if (modrm_idx >= 0 && modrm_idx < MAX_INSN_LENGTH) {
		uint8_t modrm = b[modrm_idx];
		uint8_t reg = (modrm >> 3) & 0x07;
		uint8_t rm = modrm & 0x07;
		uint8_t mod = modrm & 0xc0;

		if (reg == 4) return true;
		if (mod == 0xc0 && rm == 4) return true;
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

void inject(int insn_size)
{
	int i;
	current_insn_size = insn_size;

	for (i = 0; i < 1024; i += 2) {
		((uint8_t*)packet_buffer)[i] = 0x0f;
		((uint8_t*)packet_buffer)[i + 1] = 0x0b;
	}

	packet = (char*)packet_buffer + 256;

	for (i = 0; i < insn_size && i < MAX_INSN_LENGTH; i++) {
		((char*)packet)[i] = inj.i.bytes[i];
	}

	for (i = insn_size; i < insn_size + 32; i += 2) {
		((char*)packet)[i] = 0x0f;
		((char*)packet)[i + 1] = 0x0b;
	}

	if (!have_state) {
		__asm__ __volatile__ ("ud2\n\t");
		have_state = true;
	}

#if ARCH_X64
	__asm__ __volatile__ (
		"movq packet(%rip), %r11 \n\t"
		"leaq dummy_stack_area+32768(%rip), %rsp \n\t"
		"movq inject_state+0(%rip),  %rax \n\t"
		"movq inject_state+8(%rip),  %rbx \n\t"
		"movq inject_state+16(%rip), %rcx \n\t"
		"movq inject_state+24(%rip), %rdx \n\t"
		"movq inject_state+32(%rip), %rsi \n\t"
		"movq inject_state+40(%rip), %rdi \n\t"
		"movq inject_state+48(%rip), %r8  \n\t"
		"movq inject_state+56(%rip), %r9  \n\t"
		"movq inject_state+64(%rip), %r10 \n\t"
		"movq inject_state+80(%rip), %r12 \n\t"
		"movq inject_state+88(%rip), %r13 \n\t"
		"movq inject_state+96(%rip), %r14 \n\t"
		"movq inject_state+104(%rip), %r15 \n\t"
		"movq inject_state+112(%rip), %rbp \n\t"
		"jmp *%r11 \n\t"
	);
#else
	__asm__ __volatile__ (
		"movl packet, %edx \n\t"
		"leal dummy_stack_area+32768, %esp \n\t"
		"movl inject_state+0,  %eax \n\t"
		"movl inject_state+4,  %ebx \n\t"
		"movl inject_state+8,  %ecx \n\t"
		"movl inject_state+16, %esi \n\t"
		"movl inject_state+20, %edi \n\t"
		"movl inject_state+24, %ebp \n\t"
		"jmp *%edx \n\t"
	);
#endif

	__asm__ __volatile__ (
		".globl resume \n\t"
		"resume:       \n\t"
	);
}

LONG WINAPI veh_handler(PEXCEPTION_POINTERS pExceptionInfo)
{
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

	int insn_length = (int)(fault_ip - (uintptr_t)packet);
	if (insn_length < 0 || insn_length > MAX_INSN_LENGTH) {
		insn_length = JMP_LENGTH;
	}

	DWORD code = pExceptionInfo->ExceptionRecord->ExceptionCode;
	uint32_t signum = 0;
	uint32_t si_code = 0;
	uint32_t addr = (uint32_t)-1;

	switch (code) {
		case EXCEPTION_ILLEGAL_INSTRUCTION:
		case EXCEPTION_PRIV_INSTRUCTION:
			if (fault_ip >= (uintptr_t)packet + current_insn_size) {
				signum = SIGTRAP;
				si_code = 1;
				insn_length = current_insn_size;
			} else {
				signum = SIGILL;
				si_code = 1;
			}
			break;
		case EXCEPTION_ACCESS_VIOLATION:
		case EXCEPTION_IN_PAGE_ERROR:
			signum = SIGSEGV;
			si_code = (uint32_t)pExceptionInfo->ExceptionRecord->ExceptionInformation[0];
			addr = (uint32_t)pExceptionInfo->ExceptionRecord->ExceptionInformation[1];
			break;
		case EXCEPTION_DATATYPE_MISALIGNMENT:
			signum = SIGBUS;
			si_code = 1;
			addr = (uint32_t)(uintptr_t)pExceptionInfo->ExceptionRecord->ExceptionAddress;
			break;
		case EXCEPTION_FLT_DENORMAL_OPERAND:
		case EXCEPTION_FLT_DIVIDE_BY_ZERO:
		case EXCEPTION_FLT_INEXACT_RESULT:
		case EXCEPTION_FLT_INVALID_OPERATION:
		case EXCEPTION_FLT_OVERFLOW:
		case EXCEPTION_FLT_STACK_CHECK:
		case EXCEPTION_FLT_UNDERFLOW:
		case EXCEPTION_INT_DIVIDE_BY_ZERO:
		case EXCEPTION_INT_OVERFLOW:
			signum = SIGFPE;
			si_code = 1;
			break;
		default:
			signum = SIGSEGV;
			si_code = 0;
			break;
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
				if (result.length != inj.last_len && inj.index < result.length - 1) {
					inj.index++;
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
		switch (output) {
			case TEXT:
				sync_fprintf(stdout, "x: "); print_mc(stdout, 16);
				sync_fprintf(stdout, "... (backward_branch)\n");
				sync_fflush(stdout, false);
				break;
			case RAW:
				result = (result_t){0,0,0,0,0};
				give_result(stdout);
				break;
			default:
				assert(0);
		}
		return move_next_instruction();
	}

	if (is_rip_relative_write(inj.i.bytes)) {
		switch (output) {
			case TEXT:
				sync_fprintf(stdout, "x: "); print_mc(stdout, 16);
				sync_fprintf(stdout, "... (rip_rel_write)\n");
				sync_fflush(stdout, false);
				break;
			case RAW:
				result = (result_t){0,0,0,0,0};
				give_result(stdout);
				break;
			default:
				assert(0);
		}
		return move_next_instruction();
	}

	if (modifies_sp(inj.i.bytes)) {
		switch (output) {
			case TEXT:
				sync_fprintf(stdout, "x: "); print_mc(stdout, 16);
				sync_fprintf(stdout, "... (modifies_sp)\n");
				sync_fflush(stdout, false);
				break;
			case RAW:
				result = (result_t){0,0,0,0,0};
				give_result(stdout);
				break;
			default:
				assert(0);
		}
		return move_next_instruction();
	}

	i = 0;
	while (opcode_blacklist[i].opcode) {
		if (has_opcode(opcode_blacklist[i].opcode, opcode_blacklist[i].len)) {
			switch (output) {
				case TEXT:
					sync_fprintf(stdout, "x: "); print_mc(stdout, 16);
					sync_fprintf(stdout, "... (%s)\n", opcode_blacklist[i].reason);
					sync_fflush(stdout, false);
					break;
				case RAW:
					result = (result_t){0,0,0,0,0};
					give_result(stdout);
					break;
				default:
					assert(0);
			}
			return move_next_instruction();
		}
		i++;
	}

	i = 0;
	while (prefix_blacklist[i].prefix) {
		if (has_prefix((uint8_t*)prefix_blacklist[i].prefix)) {
			switch (output) {
				case TEXT:
					sync_fprintf(stdout, "x: "); print_mc(stdout, 16);
					sync_fprintf(stdout, "... (%s)\n", prefix_blacklist[i].reason);
					sync_fflush(stdout, false);
					break;
				case RAW:
					result = (result_t){0,0,0,0,0};
					give_result(stdout);
					break;
				default:
					assert(0);
			}
			return move_next_instruction();
		}
		i++;
	}

	if (prefix_count() > config.max_prefix || (!config.allow_dup_prefix && has_dup_prefix())) {
		switch (output) {
			case TEXT:
				sync_fprintf(stdout, "x: "); print_mc(stdout, 16);
				sync_fprintf(stdout, "... (%s)\n", "prefix violation");
				sync_fflush(stdout, false);
				break;
			case RAW:
				result = (result_t){0,0,0,0,0};
				give_result(stdout);
				break;
			default:
				assert(0);
		}
		return move_next_instruction();
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

void give_result(FILE* f)
{
	uint8_t* code;
	size_t code_size;
	uint64_t address;
	switch (output) {
		case TEXT:
			switch (mode) {
				case BRUTE:
				case TUNNEL:
				case RAND:
				case DRIVEN:
					sync_fprintf(f, " %s", expected_length == result.length ? " " : ".");
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
			code = inj.i.bytes;
			code_size = MAX_INSN_LENGTH;
			address = (uintptr_t)packet_buffer;
		
			if (cs_disasm_iter(capstone_handle, (const uint8_t**)&code, &code_size, &address, capstone_insn)) {
#if RAW_REPORT_DISAS_MNE 
				strncpy(disas.mne, capstone_insn[0].mnemonic, RAW_DISAS_MNEMONIC_BYTES);
#endif
#if RAW_REPORT_DISAS_OPS
				strncpy(disas.ops, capstone_insn[0].op_str, RAW_DISAS_OP_BYTES);
#endif
#if RAW_REPORT_DISAS_LEN
				disas.len = (int)(address - (uintptr_t)packet_buffer);
#endif
#if RAW_REPORT_DISAS_VAL
				disas.val = true;
#endif
			}
			else {
#if RAW_REPORT_DISAS_MNE 
				strncpy(disas.mne, "(unk)", RAW_DISAS_MNEMONIC_BYTES);
#endif
#if RAW_REPORT_DISAS_OPS
				strncpy(disas.ops, " ", RAW_DISAS_OP_BYTES);
#endif
#if RAW_REPORT_DISAS_LEN
				disas.len = (int)(address - (uintptr_t)packet_buffer);
#endif
#if RAW_REPORT_DISAS_VAL
				disas.val = false;
#endif
			}
#if RAW_REPORT_DISAS_MNE || RAW_REPORT_DISAS_OPS || RAW_REPORT_DISAS_LEN
			sync_fwrite(&disas, sizeof(disas), 1, stdout);
#endif
#endif
			sync_fwrite(inj.i.bytes, RAW_REPORT_INSN_BYTES, 1, stdout);
			sync_fwrite(&result, sizeof(result), 1, stdout);
			break;
		default:
			assert(0);
	}
	sync_fflush(stdout, false);
}

void usage(void)
{
	printf("injector [-b|-r|-t|-d] [-R|-T] [-x] [-0] [-D] [-N]\n");
	printf("\t[-s seed] [-B brute_depth] [-P max_prefix]\n");
	printf("\t[-i instruction] [-e instruction]\n");
	printf("\t[-c core] [-X blacklist]\n");
	printf("\t[-j jobs] [-l range_bytes]\n");
}

void help(void)
{
	printf("injector [OPTIONS...]\n");
	printf("\t[-b|-r|-t|-d] ....... mode: brute, random, tunnel, directed (default: tunnel)\n");
	printf("\t[-R|-T] ............. output: raw, text (default: text)\n");
	printf("\t[-x] ................ show tick (default: %d)\n", config.show_tick);
	printf("\t[-0] ................ allow null dereference (default: %d)\n", config.enable_null_access);
	printf("\t[-D] ................ allow duplicate prefixes (default: %d)\n", config.allow_dup_prefix);
	printf("\t[-N] ................ no nx bit support (default: %d)\n", config.nx_support);
	printf("\t[-s seed] ........... in random search, seed (default: time(0))\n");
	printf("\t[-B brute_depth] .... in brute search, maximum search depth (default: %d)\n", config.brute_depth);
	printf("\t[-P max_prefix] ..... maximum number of prefixes to search (default: %d)\n", config.max_prefix);
	printf("\t[-i instruction] .... instruction at which to start search, inclusive (default: 0)\n");
	printf("\t[-e instruction] .... instruction at which to end search, exclusive (default: ff..ff)\n");
	printf("\t[-c core] ........... core on which to perform search (default: any)\n");
	printf("\t[-X blacklist] ...... blacklist the specified instruction\n");
	printf("\t[-j jobs] ........... number of simultaneous jobs to run (default: %d)\n", config.jobs);
	printf("\t[-l range_bytes] .... number of base instruction bytes in each sub range (default: %d)\n", config.range_bytes);
}

void init_config(int argc, char** argv)
{
	int c, i, j;
	opterr = 0;
	bool seed_given = false;
	while ((c = getopt(argc, argv, "?brtdRTx0Ns:DB:P:S:i:e:c:X:j:l:")) != -1) {
		switch (c) {
			case '?':
				help();
				exit(-1);
				break;
			case 'b':
				mode = BRUTE;
				break;
			case 'r':
				mode = RAND;
				break;
			case 't':
				mode = TUNNEL;
				break;
			case 'd':
				mode = DRIVEN;
				break;
			case 'R':
				output = RAW;
				break;
			case 'T':
				output = TEXT;
				break;
			case 'x':
				config.show_tick = true;
				break;
			case '0':
				config.enable_null_access = true;
				break;
			case 'N':
				config.nx_support = false;
				break;
			case 's':
				sscanf(optarg, "%ld", &config.seed);
				seed_given = true;
				break;
			case 'P':
				sscanf(optarg, "%d", &config.max_prefix);
				break;
			case 'B':
				sscanf(optarg, "%d", &config.brute_depth);
				break;
			case 'D':
				config.allow_dup_prefix = true;
				break;
			case 'i':
				i = 0;
				while (optarg[i * 2] && optarg[i * 2 + 1] && i < MAX_INSN_LENGTH) {
					unsigned int k;
					sscanf(optarg + i * 2, "%02x", &k);
					total_range.start.bytes[i] = k;
					i++;
				}
				total_range.start.len = i;
				while (i < MAX_INSN_LENGTH) {
					total_range.start.bytes[i] = 0;
					i++;
				}
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
				while (i < MAX_INSN_LENGTH) {
					total_range.end.bytes[i] = 0;
					i++;
				}
				break;
			case 'c':
				config.force_core = true;
				sscanf(optarg, "%d", &config.core);
				break;
			case 'X':
				j = 0;
				while (opcode_blacklist[j].opcode) {
					j++;
				}
				opcode_blacklist[j].opcode = (uint8_t*)malloc(strlen(optarg) / 2 + 1);
				assert(opcode_blacklist[j].opcode);
				i = 0;
				while (optarg[i * 2] && optarg[i * 2 + 1]) {
					unsigned int k;
					sscanf(optarg + i * 2, "%02x", &k);
					opcode_blacklist[j].opcode[i] = (uint8_t)k;
					i++;
				}
				opcode_blacklist[j].len = i;
				opcode_blacklist[j].reason = "user_blacklist";
				opcode_blacklist[++j] = (ignore_op_t){NULL, 0, NULL};
				break;
			case 'j':
				sscanf(optarg, "%d", &config.jobs);
				break;
			case 'l':
				sscanf(optarg, "%d", &config.range_bytes);
				break;
			default:
				usage();
				exit(-1);
		}
	}

	if (optind != argc) {
		usage();
		exit(1);
	}

	if (!seed_given) {
		config.seed = (long)time(0);
	}
}

void pin_core(void)
{
	if (config.force_core) {
		DWORD_PTR mask = ((DWORD_PTR)1) << config.core;
		if (!SetProcessAffinityMask(GetCurrentProcess(), mask)) {
			printf("error: failed to set cpu\n");
			exit(1);
		}
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

	packet_buffer = VirtualAlloc(NULL, PAGE_SIZE * 2, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	assert(packet_buffer != NULL);

#if USE_CAPSTONE
	if (cs_open(CS_ARCH_X86, CS_MODE, &capstone_handle) != CS_ERR_OK) {
		exit(1);
	}
	cs_option(capstone_handle, CS_OPT_DETAIL, CS_OPT_ON);
	capstone_insn = cs_malloc(capstone_handle);
#endif

	AddVectoredExceptionHandler(1, veh_handler);

	initialize_ranges();

	while (move_next_range()) {
		while (move_next_instruction()) {
			pretext();

			int expected_len = MAX_INSN_LENGTH;
#if USE_CAPSTONE
			uint8_t* code = inj.i.bytes;
			size_t code_size = MAX_INSN_LENGTH;
			uint64_t address = (uintptr_t)packet_buffer;
			if (cs_disasm_iter(capstone_handle, (const uint8_t**)&code, &code_size, &address, capstone_insn)) {
				expected_len = (int)(address - (uintptr_t)packet_buffer);
			}
#endif
			if (expected_len < 1) expected_len = 1;
			if (expected_len > MAX_INSN_LENGTH) expected_len = MAX_INSN_LENGTH;

			inject(expected_len);

			if (result.length < 1 || result.length > MAX_INSN_LENGTH) {
				result.length = expected_len;
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

	VirtualFree(packet_buffer, 0, MEM_RELEASE);
	free_ranges();
	CloseHandle(pool_mutex);
	CloseHandle(output_mutex);

	return 0;
}
