from pwn import *
# encoding:

"""
flag = b"{r3vv1ng_w4s_th3_e4sy_p4rt}"
last = 0x69
out = b""
def p(x):
    num = ""
    x = bin(x)[2:].rjust(8, '0')
    print(x)
    for i in range(8):
        num += x[4*(i%2)+(i//2)]
    return p8(int(num,2))

#"3dff64af47cd408f12dd75fd36e1538d14f2529c70fd35ff40a630fd7cad75ff00e630ec40cd559f24e45cba448d44c9549f24e9599d"
for b in flag:
    out += p(((b & last) ^ 0x54)) + p(((b & (last ^ 0xff)) ^ 0xed))
    last = ((((b & last) ^ 0x54)) + ((b & (last ^ 0xff)) ^ 0xed)) & 0xff
print(out)
print(out.hex())
"""

# decoding:

in_memory = bytes.fromhex("5bff38dd35f120d506f33bfb1ea927d112ae26d22afb1bff209c0afb7ad93bff00bc0af820f133d718b872ce30d130e132d718e963d3")
decoded = b""
for b in in_memory:
    num = bin(b)[2:].rjust(8, '0')
    decoded += p8(int(num[::2] + num[1::2],2))
print(decoded.hex())
# could also extract from memory / patch bytecode to print these bytes...

flag = b""
x = 0x69 # encryption value
for i in range(len(decoded) // 2):
    b1, b2 = decoded[2*i:2*i+2]
    nxt = (b1 + b2)&0xff
    
    b1 = b1 ^ 0x54
    b2 = b2 ^ 0xed

    o = 0
    for i in range(8):
        if x & (1<<i):
            o |= (b1) & (1<<i)
        else:
            o |= (b2) & (1<<i)
    flag += p8(o)
    x = nxt
print(flag)
