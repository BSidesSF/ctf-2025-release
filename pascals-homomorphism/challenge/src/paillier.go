package main

import (
    "bufio"
    "fmt"
    "io/ioutil"
    "os"
    "path"
    "strings"
    "syscall"
    "math/big"
    cryptor "crypto/rand"
    //"strconv"
)

type fullkey struct {
	weak bool
	streng_str string
	size int
    n, g, lam, u *big.Int
}


var (
    flag1, flag2 string
)

const (
	dec_lim = 2000
	weak_prime = 96
	strong_prime = 512
)


const prog_name = "paillier"

const help_text = `

Commands:
    help                 // Prints this help

    help info            // Details about this tool
    help strength        // Information about weak/strong keys

    genkey <weak|strong> // Generate a weak or strong key
    showkey              // Display the current key

    getflag              // Get an encrypted flag

    encrypt              // Encrypt a message
    decrypt              // Decryption oracle (only available for strong keys)

    exit                 // Exit the digital citizen registery
`


const help_info_text = `
This tool implements Pascal Paillier's cryptosystem.

The design is quite similar to RSA but relies on a different problem
than the RSA Problem. However, like RSA it can be broken by factoring
N.

This tool will generate Paillier keys (and give you the public parts)
and let you encrypt messages with the given key. Decryption is also
available but only when using "strong" keys (see "help strength") and
the size of the ciphertext is limited too.

See https://en.wikipedia.org/wiki/Paillier_cryptosystem for the
mathematical details.
`

const help_strength_text = `
This tool can generate two different key sizes:

A "weak" size which offers no real security because N is too small and
can easily be factored. This size is available as a warm-up to
familiarize yourself with the Paillier system. The "decrypt" command
is not available when using weak keys.

A "strong" size which is big enough to resist casual factoring. A
truly strong key would need to be larger but that is unnecessarily
cumbersome for the purpose of this tool.

The "getflag" command will choose a flag based on the current key size
and encrypt the flag. The first flag is available when using a weak
key and the second with a strong key.
`


func main() {

    startup()

    input := bufio.NewScanner(os.Stdin)
    scanbuffer := make([]byte, 65536)
    input.Buffer(scanbuffer, 65536)

	cur_key := gen_new_key(true) // weak by default

	// c := enc_m(cur_key, big.NewInt(12345))

 	// fmt.Fprintf(os.Stdout, "debug: c: %s\n", c.Text(10))
	// m := dec_c(cur_key, c)
	// fmt.Fprintf(os.Stdout, "debug: m: %s\n", m.Text(10))

    fmt.Fprint(os.Stdout, "\nTry \"help\" for a list of commands\n")

    exit := false

    for !exit {
        fmt.Fprintf(os.Stdout, "\n%s> ", prog_name)
        ok := input.Scan()
        if !ok {
            fmt.Fprintln(os.Stdout, "")
            break
        }

        text := input.Text()

        if len(text) == 0 {
            continue
        }

        tokens := strings.Split(text, " ")

        switch tokens[0] {

        case "help":
            if len(tokens) > 1 {
                switch tokens[1] {
				case "info":
                    fmt.Fprintf(os.Stdout, "%s", help_info_text)

				case "strength":
                    fmt.Fprintf(os.Stdout, "%s", help_strength_text)

                }
            } else {
                print_help()
            }

		case "genkey":
            if len(tokens) > 1 {
                switch tokens[1] {
				case "weak":
					cur_key = gen_new_key(true)

				case "strong":
					cur_key = gen_new_key(false)

				default:
					fmt.Fprintf(os.Stdout, "only weak or strong is allowed\n")
					print_help()
                }
            } else {
				fmt.Fprintf(os.Stdout, "genkey requires a strength\n")
                print_help()
            }

		case "showkey":
			fmt.Fprintf(os.Stdout, "Current key (%s -- %d bits)\n", cur_key.streng_str, cur_key.size)
			fmt.Fprintf(os.Stdout, "n: %s\n", cur_key.n.Text(10))
			fmt.Fprintf(os.Stdout, "g: n + 1\n")

		case "getflag":
			var c *big.Int
			var fnum int
			if cur_key.weak {
				fnum = 1
				c = enc_m(cur_key, new(big.Int).SetBytes([]byte(flag1)))
			} else {
				fnum = 2
				c = enc_m(cur_key, new(big.Int).SetBytes([]byte(flag2)))
			}
			fmt.Fprintf(os.Stdout, "Encrypted flag %d (%s): %s\n", fnum, cur_key.streng_str, c.Text(10))

		case "encrypt":
			fmt.Fprintf(os.Stdout, "\nNumber, m, to encrypt? ")
            ok = input.Scan()
            if !ok {
                fmt.Fprintln(os.Stdout, "Error reading input!")
                break
            }

            m, ok := new(big.Int).SetString(input.Text(), 10)
            if !ok || m == nil {
                fmt.Fprintln(os.Stdout, "Error parsing provided number")
                break
            }

			if cur_key.n.Cmp(m) <= 0 {
				fmt.Fprintln(os.Stdout, "Error, m must be smaller than n!")
				break
			}

			c := enc_m(cur_key, m)

			fmt.Fprintf(os.Stdout, "Ciphertext for m: %s\n", c.Text(10))

		case "decrypt":
			if cur_key.weak {
				fmt.Fprintln(os.Stdout, "Error, decryption oracle not available for weak keys")
                break
			}

			fmt.Fprintf(os.Stdout, "\nNumber, c, to decrypt? ")
            ok = input.Scan()
            if !ok {
                fmt.Fprintln(os.Stdout, "Error reading input!")
                break
            }

            c, ok := new(big.Int).SetString(input.Text(), 10)
            if !ok || c == nil {
                fmt.Fprintln(os.Stdout, "Error parsing provided c")
                break
            }

			if new(big.Int).Exp(big.NewInt(2), big.NewInt(dec_lim), nil).Cmp(c) <= 0 {
				fmt.Fprintf(os.Stdout, "Error, the decryption oracle is limited to ciphertexts less than %d bits\n", dec_lim)
				break
			}

			m := dec_c(cur_key, c)

			fmt.Fprintf(os.Stdout, "Plaintext for c: %s\n", m.Text(10))


        case "h":
            print_help()

        case "?":
            print_help()

        case "exit":
            exit = true

        case "quit":
            exit = true

        case "flag":
            fmt.Fprintf(os.Stdout, "lolz you typed 'flag' but that isn't a command. You didn't really think that was going to work, did you?\n")
            exit = true

        case "^d":
            fmt.Fprintf(os.Stdout, "Uhmmm... You do realize that the '^' in '^d' isn't a literal '^' right??")
			exit = true

        default:
            fmt.Fprintf(os.Stdout, "%s: `%s` command not found. Try \"help\" for a list of commands.", prog_name, tokens[0])

        }
    }

}




func print_help() {
    fmt.Fprintf(os.Stdout, "\n%s help:\n%s", prog_name, help_text)
}


func startup() {

    changeBinDir()
    limitTime(5)

    bannerbuf, err := ioutil.ReadFile("./banner.txt")

    if err != nil {
        fmt.Fprintf(os.Stderr, "Unable to read banner: %s\n", err.Error())
        os.Exit(1)
    }
    fmt.Fprint(os.Stdout, string(bannerbuf))

    fbuf1, err := ioutil.ReadFile("./flag_1.txt")
    if err != nil {
        fmt.Fprintf(os.Stderr, "Unable to read flag 1: %s\n", err.Error())
        os.Exit(1)
    }
    flag1 = string(fbuf1)

	fbuf2, err := ioutil.ReadFile("./flag_2.txt")
    if err != nil {
        fmt.Fprintf(os.Stderr, "Unable to read flag 2: %s\n", err.Error())
        os.Exit(1)
    }
    flag2 = string(fbuf2)

}


// Change to working directory
func changeBinDir() {
    // read /proc/self/exe
    if dest, err := os.Readlink("/proc/self/exe"); err != nil {
        //fmt.Fprintf(os.Stderr, "Error reading link: %s\n", err)
        return
    } else {
        dest = path.Dir(dest)
        if err := os.Chdir(dest); err != nil {
            fmt.Fprintf(os.Stderr, "Error changing directory: %s\n", err)
        }
    }
}


// Limit CPU time to certain number of seconds
func limitTime(secs int) {
    lims := &syscall.Rlimit{
        Cur: uint64(secs),
        Max: uint64(secs),
    }
    if err := syscall.Setrlimit(syscall.RLIMIT_CPU, lims); err != nil {
        if inner_err := syscall.Getrlimit(syscall.RLIMIT_CPU, lims); inner_err != nil {
            fmt.Fprintf(os.Stderr, "Error getting limits: %s\n", inner_err)
        } else {
            if lims.Cur > 0 {
                // A limit was set elsewhere, we'll live with it
                return
            }
        }
        fmt.Fprintf(os.Stderr, "Error setting limits: %s", err)
        os.Exit(-1)
    }
}



func enc_m(key *fullkey, m *big.Int) *big.Int {

retry_r:
	r, err := cryptor.Int(cryptor.Reader, key.n)

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: unable to generate r for encryption\n")
		os.Exit(1)
	}

	if big.NewInt(1).Cmp(new(big.Int).GCD(nil, nil, r, key.n)) != 0 {
		goto retry_r
	}

	n2 := new(big.Int).Mul(key.n, key.n)

	gm := new(big.Int).Exp(key.g, m, n2)
	rn := new(big.Int).Exp(r, key.n, n2)

	c := new(big.Int).Mod(new(big.Int).Mul(gm, rn), n2)

	return c
}


func l(x *big.Int, n *big.Int) *big.Int {

	return new(big.Int).Div(new(big.Int).Add(x, big.NewInt(-1)), n)
}


func dec_c(key *fullkey, c *big.Int) *big.Int {

	n2 := new(big.Int).Mul(key.n, key.n)

	x := new(big.Int).Exp(c, key.lam, n2)

	m := new(big.Int).Mod(new(big.Int).Mul(l(x, key.n), key.u), key.n)

	return m
}


func gen_new_key(weak bool) *fullkey {

	var streng_str string
	var size int
	if weak {
		streng_str = "weak"
		size = weak_prime
	} else {
		streng_str = "strong"
		size = strong_prime
	}

    key := new(fullkey)

    fails := 0
retry_key:

	p, err := cryptor.Prime(cryptor.Reader, size)

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: unable to generate secure prime\n")
		os.Exit(1)
	}

	q, err := cryptor.Prime(cryptor.Reader, size)

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: unable to generate secure prime\n")
		os.Exit(1)
	}

	// We want p and q to be very close in size
    // Check p < q < 2p
    if p.Cmp(q) < 0 {
        if q.Cmp(new(big.Int).Mul(p, big.NewInt(2))) > 0 {
            goto retry_key
        }
    }

    // Now check q < p < 2q
    if q.Cmp(p) < 0 {
        if p.Cmp(new(big.Int).Mul(q, big.NewInt(2))) > 0 {
            goto retry_key
        }
    }

    n := new(big.Int).Mul(p, q)

    pm1 := new(big.Int).Add(p, big.NewInt(-1))
    qm1 := new(big.Int).Add(q, big.NewInt(-1))
    // Carmichael totient function
	// carm := new(big.Int).Div(new(big.Int).Mul(pm1, qm1), new(big.Int).GCD(nil, nil, pm1, qm1))
	// Euler totient function
	euler := new(big.Int).Mul(pm1, qm1)

	g := new(big.Int).Add(n, big.NewInt(1))

	u := new(big.Int).ModInverse(euler, n)

    if u == nil {
        if (fails > 5) {
            fmt.Fprintf(os.Stderr, "Error: unable to generate u!\n")
            os.Exit(1)
        } else {
            fails++
            goto retry_key
        }
    }

    //fmt.Fprintf(os.Stdout, "debug: d: %s\n", d.Text(10))
    //fmt.Fprintf(os.Stdout, "debug: carm: %s\n", carm.Text(10))

	key.weak = weak
    key.n = n
    key.g = g
	key.lam = euler
	key.u = u
	key.size = size * 2
	key.streng_str = streng_str

	fmt.Fprintf(os.Stdout, "New %s key generated (%d bits)\n", key.streng_str, key.size)
	fmt.Fprintf(os.Stdout, "n: %s\n", key.n.Text(10))
	fmt.Fprintf(os.Stdout, "g: n + 1\n")

    return key
}
