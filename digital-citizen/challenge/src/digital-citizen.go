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
    "strconv"
)

type fullkey struct {
	gen_type int
    fname, lname string
    messages []string
    p, q, n, e, d *big.Int
}


var (
    flag1 string
	flag2 string
    keylist []*fullkey
)


const prog_name = "digital-citizen"

const help_text = `

Commands:
    help                 // Prints this help

    help types           // Display help about the key types

    listkeys             // Display all current public keys
    genkey               // Generate a new keypair

    listmsgs             // Get a list of unread messages
    sendmsg              // Send a secure message
    readmsg              // Read a secure message

    exit                 // Exit the digital citizen registery
`


const help_types_text = `
Our keys are generated with a Renesas AE45C1 smartcard clone which
offers two modes of randomness: true, and pseudo.

pseudo:
In this mode, the card uses a hardware entropy source which is
whitened and the used to seed a cryptographically secure PRNG. Keys
are generated using this PRNG. If a weakness in the PRNG is found keys
generated this way could be broken.

true:
In this mode, the card directly uses entropy from the hardware
generator without any post-processing
`


func main() {

    startup()

    input := bufio.NewScanner(os.Stdin)
    scanbuffer := make([]byte, 65536)
    input.Buffer(scanbuffer, 65536)


    // Make admin 1 key
    a1key := gen_new_key(2) // force p = rand, q = pattern len 7

    a1key.fname = "DJB"
    a1key.lname = "Tanja Lange"
    a1key.messages = make([]string, 0)

    a1key.messages = append(a1key.messages, fmt.Sprintf("Dan, I think our smartcards may have errors... %s", flag1))
    keylist = append(keylist, a1key)

	// Make admin 2 key
    a2key := gen_new_key(3) // fore p = rand, q = pattern len 7 + 48 scrambled bits

    a2key.fname = "Coppersmith"
    a2key.lname = "Howgrave-Graham"
    a2key.messages = make([]string, 0)

    a2key.messages = append(a2key.messages, fmt.Sprintf("Even when the HW RNG gets going it isn't secure %s", flag2))
    keylist = append(keylist, a2key)

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
                    case "types":
                    fmt.Fprintf(os.Stdout, "%s", help_types_text)

                }
            } else {
                print_help()
            }

        case "h":
            print_help()

        case "?":
            print_help()

        case "listkeys":
            for i, k := range keylist {
                fmt.Fprintf(os.Stdout, "\nCitizen %2d. (%s %s)\n", i, k.fname, k.lname)
				fmt.Fprintf(os.Stdout, "Public n: 0x%s\n", (k.n).Text(16))
				fmt.Fprintf(os.Stdout, "Public e: 0x%s\n", (k.e).Text(16))
            }

        case "listmsgs":
            for i, k := range keylist {
                fmt.Fprintf(os.Stdout, "Citizen %2d. (%s, %s): %d unread messages\n", i, k.fname, k.lname, len(k.messages))
            }

        case "sendmsg":
            fmt.Fprint(os.Stdout, "\nEnter citizen (by number) to send message? ")
            ok = input.Scan()
            if !ok {
                fmt.Fprintln(os.Stdout, "Error reading input!")
                break
            }
            unum := input.Text()

            intin, err := strconv.Atoi(unum)

            if err != nil {
                fmt.Fprintln(os.Stdout, "Error, could not interpret input as number!")
                break
            }

            if intin < 0 && intin >= len(keylist) {
                fmt.Fprintf(os.Stdout, "Error, citizen %d does not exist!", intin)
                break
            }

            fmt.Fprintf(os.Stdout, "\nMessage for citizen %d? ", intin)
            ok = input.Scan()
            if !ok {
                fmt.Fprintln(os.Stdout, "Error reading input!")
                break
            }
            umsg := input.Text()

            keylist[intin].messages = append(keylist[intin].messages, umsg)

            fmt.Fprintln(os.Stdout, "Message sent!")


        case "readmsg":
            fmt.Fprint(os.Stdout, "\nEnter citizen (by number) to read unread messages? ")
            ok = input.Scan()
            if !ok {
                fmt.Fprintln(os.Stdout, "Error reading input!")
                break
            }
            unum := input.Text()

            intin, err := strconv.Atoi(unum)

            if err != nil {
                fmt.Fprintln(os.Stdout, "Error, could not interpret input as number!")
                break
            }

            if intin < 0 || intin >= len(keylist) {
                fmt.Fprintf(os.Stdout, "Error, citizen %d does not exist!", intin)
                break
            }

            chal, err := cryptor.Int(cryptor.Reader, new(big.Int).Exp(big.NewInt(2), big.NewInt(128), nil))

            if err != nil {
                fmt.Fprintln(os.Stdout, "Unable to generate random message!")
                os.Exit(1);
            }

            fmt.Fprintf(os.Stdout, "\nWelcome %s(?), before we continue, you must prove it's you\n", keylist[intin].fname)
            fmt.Fprintf(os.Stdout, "\nPlease provide the signature for %s : ", chal.Text(10))
            ok = input.Scan()
            if !ok {
                fmt.Fprintln(os.Stdout, "Error reading input!")
                break
            }

            chal_sig, ok := new(big.Int).SetString(input.Text(), 10)
            if !ok || chal_sig == nil {
                fmt.Fprintln(os.Stdout, "Error parsing provided signature!")
                break
            }

            verify := new(big.Int).Exp(chal_sig, keylist[intin].e, keylist[intin].n)
            if chal.Cmp(verify) != 0 {
                fmt.Fprintln(os.Stdout, "Signature validation failed!")
                //fmt.Fprintln(os.Stdout, "debug: using n: %s\n", keylist[intin].n.Text(10))
                //fmt.Fprintln(os.Stdout, "debug: using e: %s\n", keylist[intin].e.Text(10))
                //fmt.Fprintln(os.Stdout, "debug: got verify of %s\n", verify.Text(10))
                break
            }

            if len(keylist[intin].messages) == 0 {
                fmt.Fprintf(os.Stdout, "%s doesn't have any unread messages\n", keylist[intin].fname)
                break
            }

            for i, m := range keylist[intin].messages {
                fmt.Fprintf(os.Stdout, "Message %d: %s\n", i + 1, m)
            }
            // clear messages
            keylist[intin].messages = make([]string, 0)


        case "genkey":
            fmt.Fprint(os.Stdout, "\nFirst name? ")
            ok = input.Scan()
            if !ok {
                fmt.Fprintln(os.Stdout, "Error reading input!")
                break
            }
            ufname := input.Text()

            fmt.Fprint(os.Stdout, "\nLast name? ")
            ok = input.Scan()
            if !ok {
                fmt.Fprintln(os.Stdout, "Error reading input!")
                break
            }
            ulname := input.Text()

            gotyn := false
            var gen_type int
            for !gotyn {
                fmt.Fprint(os.Stdout, "\nDo you want true randomness or pseudo randomeness (true / pseudo)? ")
                ok = input.Scan()
                if !ok {
                    fmt.Fprintln(os.Stdout, "Error reading input!")
                    break
                }
                yn := input.Text()

                switch yn {
                case "true":
                    gen_type = 1
                    gotyn = true
                case "pseudo":
                    gen_type = 0
                    gotyn = true
                default:
                    fmt.Fprint(os.Stdout, "\nAnswer must be either `true` or `pseudo`. See `help types` for an explanation.")
                }
            }

            fmt.Fprintf(os.Stdout, "\nGenerating key for %s...", ufname)
            ukey := gen_new_key(gen_type)

            ukey.fname = ufname
            ukey.lname = ulname
            ukey.messages = make([]string, 0)
            ukey.messages = append(ukey.messages, fmt.Sprintf("Welcome %s, Enjoy your new digital citizen key!", ufname))

            keylist = append(keylist, ukey)

            fmt.Fprintf(os.Stdout, "\n%s, your key is ready!\n", ufname)
            fmt.Printf("Public modulus: %s\n", (ukey.n).Text(10))
            fmt.Printf("Public exponent: %s\n", (ukey.e).Text(10))
            fmt.Printf("Private exponent: %s\n", (ukey.d).Text(10))
			//fmt.Printf("Private p: %s\n", (ukey.p).Text(10))
			//fmt.Printf("Private q: %s\n", (ukey.q).Text(10))

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
        fmt.Fprintf(os.Stderr, "Error reading link: %s\n", err)
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


func roll_d(n int) int64 {

	r, _ := cryptor.Int(cryptor.Reader, big.NewInt(int64(n)))

	return r.Int64()
}


func get_prime(sec_chance int, size int, gen_type int) *big.Int {

	if size % 32 != 0 {
		fmt.Fprintf(os.Stderr, "Error: size must be a multiple of 32 bits\n")
		os.Exit(1)
	}

	// 1-in-sec_chance we just generate a secure prime
	if roll_d(sec_chance) == 0 && gen_type < 2 {
		p, err := cryptor.Prime(cryptor.Reader, size)

		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: unable to generate secure prime\n")
			os.Exit(1)
		}

		return p
	}

	// Nope, we're generating a bit pattern prime

	// figure out how long of a pattern to generate where
	// 1 is twice as likely as 3 which is twice as likely as 5 and so on
	pat_len := 1

	if gen_type < 2 {
		for roll_d(2) == 0 && pat_len < 9 {
			pat_len += 2
		}
	} else {
		pat_len = 7
	}

	pat := make([]int, pat_len)

	for i := 0; i < pat_len; i++{
		pat[i] = int(roll_d(2))
	}

	r := make([]int, size) // "random" bits

	// copy bit pattern into r
	for i := 0; i < size; i++ {
		r[i] = pat[i % pat_len]
	}

	// For every 32 bits swap upper and lower 16 bits
	for i := 0; i < (size / 32); i++ {
		for j := i * 32; j < (i * 32) + 16; j++ {
			r[j], r[j + 16] = r[j + 16], r[j]
		}
	}

	// Roll d4 to decide if we scramble 48 bits
	// This will force the usage of coppersmith
	if (gen_type == 1 && roll_d(4) == 0) || (gen_type == 3) {
		for i := size - 64; i < size - 16; i++ {
			r[i] = int(roll_d(2))
		}
	}

	// Set the top two bits
	r[0] = 1
	r[1] = 1

	// Zero out the lower 16 bits
	for i := size - 16; i < size; i++ {
		r[i] = 0
	}

	// Convert bits to big int
	q := big.NewInt(0)
	p2 := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(size - 1)), nil)
	for i := 0; i < size; i++ {
		if r[i] == 1 {
			q.Add(q, p2)
		}

		p2.Div(p2, big.NewInt(2))
	}

	// Now find the cloest prime equal or above this number
	for {
		if q.ProbablyPrime(32) == true {
			break
		} else {
			q.Add(q, big.NewInt(1))
		}
	}

	//fmt.Fprintf(os.Stdout, "debug: q: %s\n", q.Text(16))
	return q

}



func gen_new_key(gen_type int) *fullkey {

    key := new(fullkey)

    fails := 0
retry_key:

	var p *big.Int
	var q *big.Int
	if gen_type == 0 {
		p = get_prime(1, 512, gen_type)
		q = get_prime(1, 512, gen_type)
	} else if gen_type == 1 {
		p = get_prime(2, 512, gen_type)
		q = get_prime(2, 512, gen_type)
	} else {
		p = get_prime(1, 512, 0)
		q = get_prime(2, 512, gen_type)
	}

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
	carm := new(big.Int).Div(new(big.Int).Mul(pm1, qm1), new(big.Int).GCD(nil, nil, pm1, qm1))
	// Euler totient function
	//euler := new(big.Int).Mul(pm1, qm1)

    var e, d *big.Int

	// make a more traditional key
	e = big.NewInt(65537)

	d = new(big.Int).ModInverse(e, carm)
	// d = new(big.Int).ModInverse(e, euler)

    if d == nil || e == nil {
        if (fails > 5) {
            fmt.Fprintf(os.Stderr, "Error: unable to generate d! Probably (p - 1) or (q - 1) was a multiple of e or d\n")
            os.Exit(1)
        } else {
            fails++
            goto retry_key
        }
    }

    //fmt.Fprintf(os.Stdout, "debug: d: %s\n", d.Text(10))
    //fmt.Fprintf(os.Stdout, "debug: carm: %s\n", carm.Text(10))

	key.p = p
	key.q = q
    key.n = n
    key.e = e
	key.d = d
	key.gen_type = gen_type

    return key
}
