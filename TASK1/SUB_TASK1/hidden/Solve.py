from Crypto.Util.number import bytes_to_long, long_to_bytes

def rol4(x, n):
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF
def ror4(x, n):
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF

def decrypt(enc_chunk, fmt):
    s_12 = (rol4(fmt[0], 5) + ror4(fmt[1], 3)) & 0xFFFFFFFF
    s_8 = (ror4(fmt[2], 3) - rol4(fmt[3], 5)) & 0xFFFFFFFF
    chunk = (enc_chunk ^ s_12 ^ s_8) & 0xFFFFFFFF
    if enc_chunk % 2 == 0:
        fmt[0] ^= ror4(s_8, 13)
        fmt[1] ^= ror4(s_8, 15)
        fmt[2] ^= rol4(s_12, 13)
        fmt[3] ^= rol4(s_12, 11)
    else:
        fmt[0] ^= rol4(s_8, 11)
        fmt[1] ^= rol4(s_8, 13)
        fmt[2] ^= ror4(s_12, 15)
        fmt[3] ^= ror4(s_12, 13)
    return long_to_bytes(chunk)[::-1], fmt

fmt = "AlpacaHackRound8"
chunks = []
for i in range(0, len(fmt), 4):
    chunks.append(bytes_to_long(fmt[i:i+4][::-1].encode()))

"""
start = 0x0000557522600040
for i in range(0, 0x1B):
    print(hex(get_wide_dword(start + 4*i)), end=", ")
"""
enc = [
    0x9a1a86dc, 0x359b93dd, 0xeeda74d3, 0xc53c5ae8, 0x4733641c, 0xf3283bd2, 0x8b485acc, 0x874b0c74, 0x4080d638, 
    0x274ae651, 0xf5273a1, 0x3d540693, 0xc8fb1365, 0x67d2af65, 0x7def09b3, 0xe576a623, 0xff131013, 0xd0ae8d34, 
    0xf34d2c9c, 0x2f46bca1, 0x57b68798, 0xf117a21a, 0xbab0e5f0, 0xa7b56d9b, 0xac5e6aac, 0xd890f6e8, 0x9199a2b0]

dec = b""
dec_fmt = chunks.copy()
for i in range(len(enc)):
    dec_chunk, dec_fmt = decrypt(enc[i], dec_fmt)
    dec += dec_chunk
print(dec) # Alpaca{th15_f145_1s_3xc3ssiv3ly_l3ngthy_but_th1s_1s_t0_3nsur3_th4t_1t_c4nn0t_b3_e4s1ly_s01v3d_us1ng_angr}


"""
def encrypt(chunk, fmt):
    s_12 = (rol4(fmt[0], 5) + ror4(fmt[1], 3)) & 0xFFFFFFFF
    s_8 = (ror4(fmt[2], 3) - rol4(fmt[3], 5)) & 0xFFFFFFFF
    s_4 = bytes_to_long(chunk[::-1].encode()) ^ s_12 ^ s_8
    new_chunk = s_4 & 0xFFFFFFFF
    if s_4 % 2 == 0:
        fmt[0] ^= ror4(s_8, 13)
        fmt[1] ^= ror4(s_8, 15)
        fmt[2] ^= rol4(s_12, 13)
        fmt[3] ^= rol4(s_12, 11)
    else:
        fmt[0] ^= rol4(s_8, 11)
        fmt[1] ^= rol4(s_8, 13)
        fmt[2] ^= ror4(s_12, 15)
        fmt[3] ^= ror4(s_12, 13)
    return new_chunk, fmt

_input = "KCSC{HelloWorld}"
enc = []
enc_fmt = chunks.copy()
for i in range(0, len(_input), 4):
    enc_chunk, enc_fmt = encrypt(_input[i:i+4], enc_fmt)
    enc.append(enc_chunk)
"""