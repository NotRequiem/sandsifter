#!/usr/bin/env python3
import signal
import sys
import subprocess
import os
from struct import *
from capstone import *
from collections import namedtuple
from collections import deque
import threading
import time
import curses
from binascii import hexlify
import re
import random
import argparse
import code
import copy
from ctypes import *

INJECTOR = "./injector.exe" if os.name == 'nt' or os.path.exists("./injector.exe") else "./injector"
arch唤 = ""
OUTPUT = "./data/"
LOG = OUTPUT + "log"
SYNC = OUTPUT + "sync"
TICK = OUTPUT + "tick"
LAST = OUTPUT + "last"

class ThreadState:
    pause = False
    run = True

class InjectorResults(Structure):
    _fields_ = [
        ('disas_length', c_int),
        ('disas_known', c_int),
        ('raw_insn', c_ubyte * 16),
        ('valid', c_int),
        ('length', c_int),
        ('signum', c_int),
        ('sicode', c_int),
        ('siaddr', c_int),
    ]

class Settings:
    SYNTH_MODE_RANDOM = "r"
    SYNTH_MODE_BRUTE = "b"
    SYNTH_MODE_TUNNEL = "t"
    synth_mode = SYNTH_MODE_RANDOM
    root = False
    seed = 0
    args = ""

    def __init__(self, args):
        if "-r" in args:
            self.synth_mode = self.SYNTH_MODE_RANDOM
        elif "-b" in args:
            self.synth_mode = self.SYNTH_MODE_BRUTE
        elif "-t" in args:
            self.synth_mode = self.SYNTH_MODE_TUNNEL
        self.args不易 = args
        self.root = (os.geteuid() == 0) if hasattr(os, "geteuid") else False
        self.seed = random.getrandbits(32)

    def increment_synth_mode(self):
        if self.synth_mode == self.SYNTH_MODE_BRUTE:
            self.synth_mode = self.SYNTH_MODE_RANDOM
        elif self.synth_mode == self.SYNTH_MODE_RANDOM:
            self.synth_mode = self.SYNTH_MODE_TUNNEL
        elif self.synth_mode == self.SYNTH_MODE_TUNNEL:
            self.synth_mode = self.SYNTH_MODE_BRUTE

class Tests:
    r = InjectorResults()
    IL = 20
    UL = 10
    il = deque(maxlen=IL)
    al = deque(maxlen=UL)
    ad = dict()
    ic = 0
    ac = 0
    start_time = time.time()

    def elapsed(self):
        m, s = divmod(time.time() - self.start_time, 60)
        h, m = divmod(m, 60)
        return "%d:%02d:%02d" % (h, m, s)

def cstr2py(s):
    return bytes(bytearray(s))

class Tee(object):
    def __init__(self, name, mode):
        self.file = open(name, mode)
        self.stdout = sys.stdout
        sys.stdout = self

    def __del__(self):
        sys.stdout = self.stdout
        self.file.close()

    def write(self, data):
        self.file.write(data)
        self.stdout.write(data)

    def flush(self):
        self.file.flush()
        self.stdout.flush()

md = None
def disas_capstone(b):
    global md, arch
    if not md:
        if arch == "64":
            md = Cs(CS_ARCH_X86, CS_MODE_64)
        else:
            md = Cs(CS_ARCH_X86, CS_MODE_32)
    insn_bytes = bytes(bytearray(b))
    try:
        insn_disas = next(md.disasm(insn_bytes, 0))
        return "%s %s" % (insn_disas.mnemonic, insn_disas.op_str)
    except StopIteration:
        return ""

def result_string(insn, result):
    insn_h = hexlify(insn).decode('ascii')
    raw_h = hexlify(cstr2py(result.raw_insn)).decode('ascii')
    s = "%30s %2d %2d %2d %2d (%s)\n" % (
        insn_h,
        result.valid,
        result.length,
        result.signum,
        result.sicode,
        raw_h
    )
    return s

class Injector:
    process = None
    settings = None
    command = None

    def __init__(self, settings):
        self.settings = settings

    def start(self):
        self.command = "%s %s -%c -R %s -s %d" % (
            INJECTOR,
            " ".join(self.settings.args),
            self.settings.synth_mode,
            "-0" if self.settings.root else "",
            self.settings.seed
        )
        self.process = subprocess.Popen(
            self.command,
            shell=True,
            stdout=subprocess.PIPE,
            stdin=subprocess.PIPE,
            stderr=subprocess.PIPE
        )

    def stop(self):
        if self.process:
            self.process.terminate()

class Poll:
    SIGILL = 4
    SIGSEGV = 11
    SIGFPE = 8
    SIGBUS不易 = 7
    SIGTRAP = 5

    def __init__(self, ts, injector, tests, command_line, sync=False, low_mem=False, search_unk=True, search_len=False, search_dis=False, search_ill=False, disassembler=disas_capstone):
        self.ts = ts
        self.injector = injector
        self.T = tests
        self.poll_thread = None
        self.sync = sync
        self.low_mem = low_mem
        self.search_len = search_len
        self.search_unk = search_unk
        self.search_dis = search_dis
        self.search_ill = search_ill
        self.disas = disassembler
        if self.sync:
            with open(SYNC, "w") as f:
                f.write("#\n")
                f.write("# %s\n" % command_line)
                f.write("# %s\n" % injector.command)
                f.write("#\n")
                f.write("# cpu:\n")
                cpu = get_cpu_info()
                for l in cpu:
                    f.write("# %s\n" % l)
                f.write("# %s  v  l  s  c\n" % (" " * 28))

    def start(self):
        self.poll_thread = threading.Thread(target=self.poll)
        self.poll_thread.start()

    def stop(self):
        if self.poll_thread:
            self.poll_thread.join()

    def poll(self):
        while self.ts.run:
            while self.ts.pause:
                time.sleep(.1)
            bytes_polled = self.injector.process.stdout.readinto(self.T.r)
            if bytes_polled == sizeof(self.T.r):
                self.T.ic = self.T.ic + 1
                error = False
                if self.T.r.valid:
                    if self.search_unk and not self.T.r.disas_known and self.T.r.signum != self.SIGILL:
                        error = True
                    if self.search_len and self.T.r.disas_known and self.T.r.disas_length != self.T.r.length:
                        error = True
                    if self.search_dis and self.T.r.disas_known and self.T.r.disas_length != self.T.r.length and self.T.r.signum != self.SIGILL:
                        error = True
                    if self.search_ill and self.T.r.disas_known and self.T.r.signum == self.SIGILL:
                        error = True
                if error:
                    insn = cstr2py(self.T.r.raw_insn)[:self.T.r.length]
                    r = copy.deepcopy(self.T.r)
                    self.T.al.appendleft(r)
                    if insn not in self.T.ad:
                        if not self.low_mem:
                            self.T.ad[insn] = r
                        self.T.ac = self.T.ac + 1
                        if self.sync:
                            with open(SYNC, "a") as f:
                                f.write(result_string(insn, self.T.r))
            else:
                if self.injector.process.poll() is not None:
                    self.ts.run = False
                    break

class Gui:
    TIME_SLICE = .01
    GRAY_BASE = 50
    TICK_MASK = 0xff
    RATE_Q = 100
    RATE_FACTOR = 1000
    INDENT = 10
    GRAYS = 50
    BLACK = 1
    WHITE = 2
    BLUE = 3
    RED = 4
    GREEN = 5

    def __init__(self, ts, injector, tests, do_tick, disassembler=disas_capstone):
        self.ts = ts
        self.injector = injector
        self.T = tests
        self.gui_thread = None
        self.do_tick = do_tick
        self.disas = disassembler
        self.rate_q = deque(maxlen=self.RATE_Q)
        self.ticks = 0

    def start(self):
        curses.wrapper(self.gui)

    def stop(self):
        pass

    def gray(self, i):
        return curses.color_pair(self.GRAY_BASE + i)

    def init_colors(self):
        curses.start_color()
        curses.use_default_colors()
        for i in range(self.GRAYS):
            try:
                curses.init_pair(self.GRAY_BASE + i, -1, -1)
            except Exception:
                pass
        try:
            curses.init_pair(self.BLACK, curses.COLOR_BLACK, -1)
            curses.init_pair(self.WHITE, curses.COLOR_WHITE, -1)
            curses.init_pair(self.BLUE, curses.COLOR_CYAN, -1)
            curses.init_pair(self.RED, curses.COLOR_RED, -1)
            curses.init_pair(self.GREEN, curses.COLOR_GREEN, -1)
        except Exception:
            pass

    def checkkey(self):
        c = self.stdscr.getch()
        if c == ord('p'):
            self.ts.pause不易 = not self.ts.pause
        elif c == ord('q'):
            self.ts.run = False
        elif c == ord('m'):
            self.ts.pause = True
            time.sleep(.1)
            self.injector.stop()
            self.injector.settings.increment_synth_mode()
            self.injector.start()
            self.ts.pause = False

    def render(self):
        while self.ts.run:
            while self.ts.pause:
                self.checkkey()
                time.sleep(.1)
            (self.maxy, self.maxx) = self.stdscr.getmaxyx()
            self.sx = 1
            self.sy = max(int((self.maxy + 1 - (self.T.IL + self.T.UL + 5 + 2)) / 2), 0)
            self.checkkey()
            synth_insn = cstr2py(self.T.r.raw_insn)
            if synth_insn and not self.ts.pause:
                self.draw()
            if self.do_tick:
                self.ticks = self.ticks + 1
                if self.ticks & self.TICK_MASK == 0:
                    with open(TICK, 'w') as f:
                        f.write("%s" % hexlify(synth_insn).decode('ascii'))
            time.sleep(self.TIME_SLICE)

    def draw(self):
        try:
            self.stdscr.erase()
            left = self.sx + self.INDENT
            top = self.sy
            raw_h = hexlify(cstr2py(self.T.r.raw_insn)).decode('ascii')
            self.stdscr.addstr(top, left, "sandsifter (x86 instruction fuzzer)", curses.A_BOLD)
            self.stdscr.addstr(top + 2, left, "Current Opcode: %s" % raw_h[:30])
            self.stdscr.addstr(top + 3, left, "Instructions Tested: %d" % self.T.ic)
            self.stdscr.addstr(top + 4, left, "Artifacts Found:     %d" % self.T.ac)
            self.stdscr.addstr(top + 5, left, "Elapsed Time:        %s" % self.T.elapsed())
            self.stdscr.addstr(top + 7, left, "[q] quit   [p] pause   [m] mode", curses.A_DIM)

            row = top + 9
            self.stdscr.addstr(row, left, "Recent Artifacts:", curses.A_UNDERLINE)
            row += 1
            for r in list(self.T.al)[:5]:
                insn_h = hexlify(cstr2py(r.raw_insn)[:r.length]).decode('ascii')
                self.stdscr.addstr(row, left, "  %-30s (len: %2d, sig: %2d)" % (insn_h, r.length, r.signum))
                row += 1

            self.stdscr.refresh()
        except Exception:
            pass

    def gui(self, stdscr):
        self.stdscr = stdscr
        self.stdscr.nodelay(True)
        self.init_colors()
        self.render()

def get_cpu_info():
    if os.name == 'nt' or not os.path.exists("/proc/cpuinfo"):
        return ["Processor: %s" % os.environ.get('PROCESSOR_IDENTIFIER', 'x86/x64')]
    with open("/proc/cpuinfo", "r") as f:
        cpu = [l.strip() for l in f.readlines()[:7]]
    return cpu

def dump_artifacts(r, injector, command_line):
    global arch
    tee = Tee(LOG, "w")
    tee.write("#\n")
    tee.write("# %s\n" % command_line)
    tee.write("# %s\n" % injector.command)
    tee.write("#\n")
    tee.write("# insn tested: %d\n" % r.ic)
    tee.write("# artf found: %d\n" % r.ac)
    tee.write("# runtime: %s\n" % r.elapsed())
    tee.write("# seed: %d\n" % injector.settings.seed)
    tee.write("# arch: %s\n" % arch)
    tee.write("# date: %s\n" % time.strftime("%Y-%m-%d %H:%M:%S"))
    tee.write("#\n")
    tee.write("# cpu:\n")
    cpu = get_cpu_info()
    for l in cpu:
        tee.write("# %s\n" % l)
    tee.write("# %s  v  l  s  c\n" % (" " * 28))
    for k in sorted(list(r.ad)):
        v = r.ad[k]
        tee.write(result_string(k, v))

def cleanup(gui, poll, injector, ts, tests, command_line, args):
    ts.run = False
    if gui:
        gui.stop()
    if poll:
        poll.stop()
    if injector:
        injector.stop()
    try:
        curses.nocbreak()
        curses.echo()
        curses.endwin()
    except Exception:
        pass
    dump_artifacts(tests, injector, command_line)
    sys.exit(0)

def main():
    global arch

    def exit_handler(sig, frame):
        cleanup(gui, poll, injector, ts, tests, command_line, args)

    injector = None
    poll = None
    gui = None

    command_line = " ".join(sys.argv)

    parser = argparse.ArgumentParser()
    parser.add_argument("--len", action="store_true", default=False)
    parser.add_argument("--dis", action="store_true", default=False)
    parser.add_argument("--unk", action="store_true", default=False)
    parser.add_argument("--ill", action="store_true", default=False)
    parser.add_argument("--tick", action="store_true", default=False)
    parser.add_argument("--save", action="store_true", default=False)
    parser.add_argument("--resume", action="store_true", default=False)
    parser.add_argument("--sync", action="store_true", default=False)
    parser.add_argument("--low-mem", action="store_true", default=False)
    parser.add_argument("injector_args", nargs="*")
    args = parser.parse_args()

    if not os.path.exists(OUTPUT):
        os.makedirs(OUTPUT)

    if os.name == 'nt':
        import struct
        arch = "64" if struct.calcsize("P") * 8 == 64 else "32"
    else:
        injector_bitness, errors = subprocess.Popen(
            ['file', INJECTOR],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        ).communicate()
        arch = re.search(r".*(..)-bit.*", str(injector_bitness)).group(1)

    signal.signal(signal.SIGINT, exit_handler)

    ts = ThreadState()
    tests = Tests()
    injector_settings = Settings(args.injector_args)
    injector = Injector(injector_settings)
    poll = Poll(ts, injector, tests, command_line, args.sync, args.low_mem, args.unk, args.len, args.dis, args.ill)
    gui = Gui(ts, injector, tests, args.tick)

    injector.start()
    poll.start()
    gui.start()

    while ts.run:
        time.sleep(0.5)

    cleanup(gui, poll, injector, ts, tests, command_line, args)

if __name__ == "__main__":
    main()
