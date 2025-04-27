
import sys
from sage.all import *


def coppersmith(p, N):

    # Inputs
    k = 64
    p_top = p >> k
    #p_top = p

    #print(f"p_top: {p_top :x}")


    # Construct polynomial f(x) = (known_bits << k) + x
    PR = PolynomialRing(Zmod(N), 'x')
    x = PR.gen()
    f = (p_top << k) + x

    # Use Coppersmith's method to find small roots
    # bound = 2^k since x is the unknown lower k bits
    roots = f.small_roots(X=2^k, beta=0.4)  # beta is tunable

    if roots:
        x0 = int(roots[0])
        new_p = (p_top << k) + x0
        if N % new_p == 0:
            q = N // new_p
            #print("success!!")
            return q
        else:
            return None
    else:
        return None



m = int(sys.argv[2], 16)

print(f"Will run coppersmith on {m :x}")

with open(sys.argv[1]) as f:
    for p in f:
        p = p.rstrip("\n")

        p = int(p)

        #print(f"Trying with prime {p :x}")
        q = coppersmith(p, m)
        if not q is None:
            print(f"Factored {m} into {q} and {m // q}")
            print(f"p bits: {m // q :0512b}")
            print(f"q bits: {q :0512b}")
            break

