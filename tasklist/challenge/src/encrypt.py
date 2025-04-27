#!/usr/bin/env python3

import sys

DECRYPT_TEMPLATE = (
"""
#include <stdint.h>   // for uint32_t
#include <limits.h>   // for CHAR_BIT

static inline uint8_t rotl (uint8_t n, unsigned int c)
{
  const unsigned int mask = (CHAR_BIT*sizeof(n) - 1);  // assumes width is a power of 2.

  c &= mask;
  return (n<<c) | (n>>( (-c)&mask ));
}

static inline uint8_t rotr (uint8_t n, unsigned int c)
{
  const unsigned int mask = (CHAR_BIT*sizeof(n) - 1);

  c &= mask;
  return (n>>c) | (n<<( (-c)&mask ));
}

static char *decrypt(const char *val, int n) {
    static char buf[256];
    int i=0;
    const char *c = val;
    while (c && i < (int)sizeof(buf) && i < n) {
        int r = i % 14 + 2;
        if (r&1) {
            buf[i++] = (char)rotl((uint8_t)*c, r>>1);
        } else {
            buf[i++] = (char)rotr((uint8_t)*c, r>>1);
        }
        c++;
    }
    buf[i] = 0;
    return buf;
}
""")

DEFINE_TEMPLATE = "#define {} (decrypt(&__ccv[{}], {}))"

STRINGS = {
        "PINFO_NAME": "argv[0]: %s\n",
        "PINFO_FD": "fds: %d, %d\n",
        "PINFO_HEAD": "head: %p\n",
        "PINFO_PINFO": "pinfo: %p\n",
        "HACKTHEPLANET": "Hack the Planet!\n",
        "PINFO_LIBC": "libc version %s, release %s\n",
}

def rotl(v, n):
    return ((v << n) | (v >> (8 - n))) & 0xFF

def rotr(v, n):
    return ((v >> n) | (v << (8 - n))) & 0xFF

def encrypt(v):
    b = v.encode('utf-8')
    i = 0
    out = []
    for c in b:
        r = (i % 14) + 2
        if r&1:
            out.append(rotr(c, r>>1))
        else:
            out.append(rotl(c, r>>1))
        i+=1
    return out

def main(fname):
    defines = []
    data = []
    for k, v in STRINGS.items():
        e = encrypt(v)
        start = len(data)
        elen = len(e)
        data.extend(e)
        defines.append(DEFINE_TEMPLATE.format(k, start, elen))
    with open(fname, "w") as fp:
        fp.write(DECRYPT_TEMPLATE)
        fp.write("\nconst char __ccv[] = {")
        for i, c in enumerate(data):
            if i % 32:
                fp.write(" ")
            else:
                fp.write("\n\t")
            fp.write("0x{:02x},".format(c))
        fp.write("\n};\n\n");
        fp.write("\n".join(defines))


if __name__ == "__main__":
    main(sys.argv[1])
