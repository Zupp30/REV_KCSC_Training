from Crypto.Util.number import bytes_to_long, long_to_bytes

def rol4(x, n):
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF
def ror4(x, n):
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF

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

fmt = "AlpacaHackRound8"
chunks = []
for i in range(0, len(fmt), 4):
    chunks.append(bytes_to_long(fmt[i:i+4][::-1].encode()))

_input = "KCSC{HelloWorld}"
enc = []
enc_fmt = chunks.copy()
for i in range(0, len(_input), 4):
    enc_chunk, enc_fmt = encrypt(_input[i:i+4], enc_fmt)
    enc.append(enc_chunk)

print([hex(x) for x in enc])