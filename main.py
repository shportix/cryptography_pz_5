import hashlib
import time
import tracemalloc


def shifting(a, n):
    a = bin(a)[2:]
    a = "0" * (64 - len(a)) + a
    a = a[n:] + a[:n]
    a = int(a, 2)
    return a


def c_func(a):
    c = []
    for x in range(5):
        c_x = a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4]
        c.append(c_x)
    return c


def d_func(c):
    d = []
    for x in range(5):
        i_1 = (x + 4) % 5
        i_2 = (x + 1) % 5
        c_i_1 = c[i_1]
        c_i_2 = c[i_2]
        c_i_2 = shifting(c_i_2, 1)
        d.append(c_i_2 ^ c_i_1)
    return d


def theta_func(a):
    c = c_func(a)
    d = d_func(c)
    for x in range(5):
        for y in range(5):
            a[x][y] = a[x][y] ^ d[x]
    return a


def rho_func(a):
    shift_const = [
        0, 36, 3, 41, 18, 1, 44, 10, 45, 2, 62, 6, 43, 15, 61, 28, 55, 25, 21, 56, 27, 20, 39, 8, 14
    ]
    for x in range(5):
        for y in range(5):
            a[x][y] = shifting(a[x][y], shift_const[x*5+y])
    return a


def pi_func(a):
    pi_a = [[0 for _ in range(5)] for _ in range(5)]
    for x in range(5):
        for y in range(5):
            pi_a[y][(2 * x + 3 * y) % 5] = a[x][y]
    return pi_a


def chi_func(a):
    chi_a = [[0 for _ in range(5)] for _ in range(5)]
    for y in range(5):
        for x in range(5):
            chi_a[x][y] = a[x][y] ^ ((~a[(x+1) % 5][y]) & a[(x+2) % 5][y])
    return chi_a


def iota_func(a, r):
    round_const = [
        1,
        32898,
        9223372036854808714,
        9223372039002292224,
        32907,
        2147483649,
        9223372039002292353,
        9223372036854808585,
        138,
        136,
        2147516425,
        2147483658,
        2147516555,
        9223372036854775947,
        9223372036854808713,
        9223372036854808579,
        9223372036854808578,
        9223372036854775936,
        32778,
        9223372039002259466,
        9223372039002292353,
        9223372036854808704,
        2147483649,
        9223372039002292232
    ]
    a[0][0] = a[0][0] ^ round_const[r]
    return a


def byte_to_8_bytes_concat(byte_list):
    res = 0
    for i in range(8):
        res += byte_list[i] << (8*i)
    return res


def unconcat_bytes(a):
    buf = []
    for i in range(8):
        buf.append((a >> (8*i)) % 256)
    return buf


def hash_rounds(s):
    a = [[byte_to_8_bytes_concat(s[8 * (x + 5 * y):8 * (x + 5 * y) + 8]) for y in range(5)] for x in range(5)]
    for round_num in range(24):
        a = theta_func(a)
        a = rho_func(a)
        a = pi_func(a)
        a = chi_func(a)
        a = iota_func(a, round_num)
    for x in range(5):
        for y in range(5):
            s[8*(x+5*y):8*(x+5*y)+8] = unconcat_bytes(a[x][y])
    return s


def sha_3_256(plaintext: bytes):
    s = bytearray(200)
    r_byte = 136
    pudding_num = r_byte - len(plaintext) % r_byte
    if pudding_num == 1:
        plaintext += b'\x86'
    else:
        plaintext += b'\x06' + b'\x00' * (pudding_num - 2) + b'\x80'
    while len(plaintext) > 0:
        for i in range(r_byte):
            s[i] ^= plaintext[i]
        plaintext = plaintext[r_byte:]
        s = hash_rounds(s)
    s = s[:32]
    hex_s = ""
    for byte in s:
        buf = bin(byte)[2:]
        buf = hex(int(buf, 2))[2:]
        if len(buf) == 1:
            buf = "0"+buf
        hex_s += buf
    return hex_s


if __name__ == '__main__':
    word = b""
    print("custom sha-3:")
    print(sha_3_256(word))
    print("default sha-3:")
    hash_lib = hashlib.sha3_256(word)
    print(hash_lib.hexdigest())

