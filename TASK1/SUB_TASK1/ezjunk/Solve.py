from Crypto.Util.number import long_to_bytes
from ctypes import *

def customXTEA(block, s=0xE8017300, delta=0xFF58F981, key=[0x5454, 0x4602, 0x4477, 0x5E5E]):
    chunk0 = c_uint32(block[0])
    chunk1 = c_uint32(block[1])
    ss = c_uint32(s - delta * 32)
    for _ in range(32):
        ss.value += delta
        chunk1.value -= (((chunk0.value << 5) ^ (chunk0.value >> 6)) + chunk0.value) ^ (ss.value + key[(ss.value >> 11) & 3]) ^ 0x33
        chunk0.value -= (((chunk1.value << 4) ^ (chunk1.value >> 5)) + chunk1.value) ^ (ss.value + key[ss.value & 3]) ^ 0x44
    return chunk0.value, chunk1.value

enc = [0xB6DDB3A9, 0x36162C23, 0x1889FABF, 0x6CE4E73B, 0xA5AF8FC, 0x21FF8415, 0x44859557, 0x2DC227B7]
enc = [c_uint(v) for v in enc]
for i in range(len(enc)):
    for _ in range(32):
        if enc[i].value & 1:
            enc[i] = c_uint(enc[i].value ^ 0x84A6972F)
            enc[i] = c_uint(enc[i].value // 2) 
            enc[i] = c_uint(enc[i].value | 1 << 31)
        else:
            enc[i] = c_uint(enc[i].value // 2)
enc = [v.value for v in enc]
flag = b""
for i in range(0, len(enc), 2):
    block = (enc[i], enc[i+1])
    dec0, dec1 = customXTEA(block)
    dec0, dec1 = long_to_bytes(dec0), long_to_bytes(dec1)
    flag += dec0[::-1] + dec1[::-1]
print(flag)


enc = [0x5406cbb1, 0xa4a41ea2, 0x34489ac5, 0x53d68797, 0xb8e0c06f, 0x259f2db, 0x52e38d82, 0x595d5e1d]
flag = b""
for i in range(0, len(enc), 2):
    block = (enc[i], enc[i+1])
    dec0, dec1 = customXTEA(block)
    dec0, dec1 = long_to_bytes(dec0), long_to_bytes(dec1)
    flag += dec0[::-1] + dec1[::-1]
print(flag)
