#!/usr/bin/env python3

checks = {}

def first_n(v, n):
    return v & ((1 << n) - 1)

def check_4(v):
    return first_n(v, 4) % 5 == 0
checks[4] = check_4

def check_12(v):
    return first_n(v, 12) % 100 == 95
checks[12] = check_12

def check_16(v):
    return first_n(v, 16).bit_count() == 11
checks[16] = check_16

def check_18(v):
    return (first_n(v, 18) * 1234).bit_count() == 13
checks[18] = check_18

def check_21(v):
    return first_n(v, 21) % 100 == 83
checks[21] = check_21

def check_28(v):
    return first_n(v, 28) % 100 == 59
checks[28] = check_28

def check_36(v):
    return first_n(v, 36).bit_count() == 20
checks[36] = check_36

def check_38(v):
    return first_n(v, 38) % 13 == 1
checks[38] = check_38

def check_44(v):
    return first_n(v, 44) % 13 == 5
checks[44] = check_44

def check_56(v):
    return first_n(v, 56) % 101 == 31
checks[56] = check_56

def check_58(v):
    return first_n(v, 58).bit_count() == 30
checks[58] = check_58

def check_60(v):
    return first_n(v, 60) % 17 == 6
checks[60] = check_60

def check_64(v):
    return first_n(v, 64) % 177 == 62
checks[64] = check_64

def check_68(v):
    return first_n(v, 68).bit_count() == 39
checks[68] = check_68

def check_74(v):
    return (first_n(v, 74) * 5).bit_count() == 40
checks[74] = check_74

def check_80(v):
    return first_n(v, 80) % 13 == 5
checks[80] = check_80

def check_86(v):
    return first_n(v, 86) % 12345 == 11160
checks[86] = check_86

def check_92(v):
    return first_n(v, 92).bit_count() == 53
checks[92] = check_92

def check_98(v):
    return first_n(v, 98) % 17 == 7
checks[98] = check_98

def check_102(v):
    return first_n(v, 102) % 19 == 4
checks[102] = check_102

def check_108(v):
    return first_n(v, 108).bit_count() == 61
checks[108] = check_108

def check_114(v):
    return first_n(v, 114) % 11 == 10
checks[114] = check_114

def check_120(v):
    return first_n(v, 120) % 41 == 14
checks[120] = check_120

def check_122(v):
    return first_n(v, 122).bit_count() == 67
checks[122] = check_122

def check_124(v):
    return first_n(v, 124) % 13 == 2
checks[124] = check_124

def check_126(v):
    return first_n(v, 126) % 17 == 16
checks[126] = check_126

def check_127(v):
    return first_n(v, 127) % 101 == 41
checks[127] = check_127

def check_128(v):
    return first_n(v, 128) % 1003 == 735
checks[128] = check_128


def search(lim, checks):

    def bits_to_bytes(bits):
        byte_l = []

        for n in range(0, len(bits) // 8):
            byte_num = 0
            for b in range(8):
                byte_num |= bits[(n * 8) + b] << (7 - b)

            byte_l.append(byte_num)

        return bytes(byte_l)

    def search_rec(d, v, pwr, bl):
        nonlocal fcount
        nonlocal lim
        nonlocal checks

        if d in checks:
            if not checks[d](v):
                return

        if d == lim:
            print(f"Found key {bl} {bits_to_bytes(bl).hex()}")
            fcount += 1
            return

        search_rec(d + 1, v, pwr << 1, bl + [0])       # zero
        search_rec(d + 1, v + pwr, pwr << 1, bl + [1]) # one

    fcount = 0
    search_rec(0, 0, 1, [])
    print(f"Search found {fcount} for {lim} bits")


N = max(checks.keys())
search(N, checks)
