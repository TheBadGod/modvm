# simple assembler for the bytecode

import sys
from pwn import *

labels = {}

def encode_regimm(x):
    if x[0] == 'x':
        return 0x80 | int(x[1:]) # register
    elif x[0] == "'":
        return ord(x.split("'")[1])
    elif len(x) > 1 and x[1] == 'x':
        x = int(x,16)
        assert(x >= 0 and x < 0x80)
        return x
    else:
        x = int(x)
        assert(x >= 0 and x < 0x80)
        return x

def readnum(x):
    return int(x,0)

def mov(args):
    return p8(opcodes["mov"]) + p8(encode_regimm(args[0])) + p8(encode_regimm(args[1]))
def fsub(args):
    return p8(opcodes["sub"]) + p8(encode_regimm(args[0])) + p8(encode_regimm(args[1]))
def fadd(args):
    return p8(opcodes["add"]) + p8(encode_regimm(args[0])) + p8(encode_regimm(args[1]))
def fand(args):
    return p8(opcodes["and"]) + p8(encode_regimm(args[0])) + p8(encode_regimm(args[1]))
def fxor(args):
    return p8(opcodes["xor"]) + p8(encode_regimm(args[0])) + p8(encode_regimm(args[1]))
def fshl(args):
    return p8(opcodes["shl"]) + p8(encode_regimm(args[0])) + p8(encode_regimm(args[1]))
def fshr(args):
    return p8(opcodes["shr"]) + p8(encode_regimm(args[0])) + p8(encode_regimm(args[1]))

def call(args):
    if args[0][:2] == '*x':
        # indirect call...
        return p8(opcodes["call"]) + p8(0x69) + p8(0x80 | int(args[0][2:]))
    else:
        print(len(code))
        return p8(opcodes["call"]) + p16(labels[args[0]]-len(code)-3,signed=True) # pc-relative

def pr(args):
    return p8(opcodes["pr"]) + p8(encode_regimm(args[0]))
def rd(args):
    return p8(opcodes["rd"]) + p8(encode_regimm(args[0]))
def fnot(args):
    return p8(opcodes["not"]) + p8(encode_regimm(args[0]))

def ret(args):
    return p8(opcodes["ret"])

def ex(args):
    return p8(opcodes["exit"]) + p8(encode_regimm(args[0]))

def remap(args):
    return p8(opcodes["remap"]) + p8(encode_regimm(args[0])) + p8(encode_regimm(args[1]))

def jz(args):
    return p8(opcodes["jz"]) + p8(encode_regimm(args[0])) + p16(labels[args[1]]-len(code)-4)
def jl(args):
    return p8(opcodes["jl"]) + p8(encode_regimm(args[0])) + p8(encode_regimm(args[1])) + p16(labels[args[2]]-len(code)-5,signed=True)

def jmp(args):
    return p8(opcodes["jmp"]) + p16(labels[args[0]] - len(code) - 3, signed=True)

def store(args):
    return p8(opcodes["str"]) + p8(encode_regimm(args[0])) + p16(labels[args[1]]-len(code)-5,signed=True) + p8(encode_regimm(args[2]))
def ld(args):
    return p8(opcodes["ld"]) + p8(encode_regimm(args[0])) + p16(labels[args[1]]-len(code)-5,signed=True) + p8(encode_regimm(args[2]))
def adr(args):
    return p8(opcodes["adr"]) + p8(encode_regimm(args[0])) + p8(encode_regimm(args[1])) + p16(labels[args[2]]-len(code)-5,signed=True)

instructions = {
    "mov": (3, mov),
    "call": (3, call),
    "ret": (1, ret),
    "pr": (2, pr),
    "rd": (2, rd),
    "exit": (2, ex),
    "remap": (3, remap),
    "add": (3, fadd),
    "sub": (3, fsub),
    "and": (3, fand),
    "xor": (3, fxor),
    "shl": (3, fshl),
    "shr": (3, fshr),
    "not": (2, fnot),
    "jz": (4, jz),
    "jl": (5, jl),
    "jmp": (3, jmp),
    "str": (5, store),
    "ld": (5, ld),
    "adr": (5, adr),
}
opcodes = {
    "mov": 0,
    "pr": 1,
    "call": 2,
    "ret": 3,
    "remap": 4,

    "add": 5,
    "and": 6,
    "xor": 7,
    "shl": 8,
    "shr": 9,
    "not": 10,
    "jz": 11,
    "jmp": 12,
    "sub": 13,

    "str": 14,
    "ld": 15,
    "adr": 16,
    "jl": 17,
    "rd": 18,

    "exit": 0xff,
}

if len(sys.argv) < 2:
    print("Give me a file to assemble!")
    exit(0)

with open(sys.argv[1]) as f:
    d = f.read().split("\n")


# resolve labels
ip = 0
for l in d:
    l = l.strip()
    if l == "": continue
    if l[0] == '#': continue
    opcode = l.split(" ")[0]
    args = [i.strip() for i in l[len(opcode)+1:].split(",")]

    if opcode[-1] == ":":
        labels[opcode[:-1]] = ip
    elif opcode == '.db':
        ip += readnum(args[0])
    elif opcode == ".str":
        ip += len(args[0]) // 2
    elif opcode in instructions:
        ip += instructions[opcode][0]
    else:
        print("What: ", opcode, args)

# actually assemble
code = b""
for l in d:
    l = l.strip()
    if l == "": continue
    if l[0] == '#': continue
    opcode = l.split(" ")[0]
    args = [i.strip() for i in l[len(opcode)+1:].split(",")]

    if opcode[-1] == ":":
        assert(labels[opcode[:-1]] == len(code))
    elif opcode == ".db":
        code += b"\xcd"*readnum(args[0])
    elif opcode == ".str":
        code += bytes.fromhex(args[0])
    elif opcode in instructions:
        code += instructions[opcode][1](args)
    else:
        print("What: ", opcode, args)

    # fricking control flow
    if opcode == "remap":
        op1 = int(args[0])
        op2 = int(args[1])
        op1 = [k for k,v in opcodes.items() if v == op1]
        op2 = [k for k,v in opcodes.items() if v == op2]
        if len(op1) > 0 and len(op2) > 0:
            op1 = op1[0]
            op2 = op2[0]
            opcodes[op1], opcodes[op2] = opcodes[op2], opcodes[op1]
        elif len(op1) > 0:
            op1 = op1[0]
            opcodes[op1] = op2
        elif len(op2) > 0:
            op2 = op2[0]
            opcodes[op2] = op1
        else:
            # nop
            pass

print(labels)
print(code)

with open("out.bin", "wb") as f:
    f.write(code)
