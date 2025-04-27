This challenge exploits the fact that a 64-bit hash has cycles of length O(2^32). You can't brute-force the pre-image of each MD5 for several reasons:

* Doing so is O(2^64) work and there are simply too many to do
* There are collisions so you don't know which backwards branch to take

Instead you find the iterated cycle length for one of the hashes in the video and then use the timestamp of that hash to work 'backwards' by going forwards. See md5_brent.c for finding cycles and also the solution function:


    void solve() {
    
        int64_t t_known = 1999634432; /* Known, possibly future time */
        int64_t t_goal = 1742826261;  /* Current time */
        int64_t cycle_len = 3385752161;
    
        int64_t steps = (cycle_len - (t_known - t_goal)) % cycle_len;
    
        const EVP_MD *md = EVP_md5();
        EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
    
        uint8_t x[EVP_MAX_MD_SIZE];
    
        memset(x, 0, EVP_MAX_MD_SIZE);
    
        x[0] = 0xef;
        x[1] = 0x2e;
        x[2] = 0x01;
        x[3] = 0x01;
        x[4] = 0xb4;
        x[5] = 0xff;
        x[6] = 0x85;
        x[7] = 0xde;
    
        fprintf(stderr, "Running %lld steps to find state at %lld from %lld\n", steps, t_goal, t_known);
        uint64_t progress = steps / 100;
        for (int64_t i = 0; i < steps; i++) {
            if (i % progress == 0) {
                fprintf(stderr, ".");
            }
            (void)md5(mdctx, md, x, TRUNCLEN, x);
        }
    
        printf("\nState found: ");
        for (int i = 0; i < TRUNCLEN; i++) {
            printf("%02x", x[i]);
        }
        printf("\n");
    
    }


Since this will take a few min to excecute, have it find a recent time and then simply fast-forward from that time:

    #!/usr/bin/env python
    
    import sys
    import hashlib
    
    # Use faster code like md5_brent.c to find
    # a recent state that you can
    # quickly fast-forward
    known_t = 1742837767
    known_cstate = bytes.fromhex("cc9ef28a7f481569")
    
    def md5_trunc(input_bytes: bytes) -> bytes:
        if len(input_bytes) != 8:
            raise ValueError("Input must be exactly 8 bytes (64 bits).")
    
        # Compute MD5 hash
        md5_hash = hashlib.md5(input_bytes).digest()
    
        # Return the first 8 bytes (64 bits)
        return md5_hash[:8]
    
    
    cstate = known_cstate
    for i in range(int(sys.argv[1]) - known_t):
        cstate = md5_trunc(cstate)
    
    print(cstate.hex())

Then solving:

    [...]
    The current time is 2025-03-24 21:04:32 (1742850272).
    What is the current state? You have 30 seconds.

    State = ? 983630b0180d8cc4
    983630b0180d8cc4
    CTF{reverse_time_polarity}


Note: an assumption must be made when using exploiting the cycle which is that the clock is currently in the main cycle loop and not one of the branches leading into the loop. This would be much easier to justify if the lead-in to the cycle were short so the clock had definitely been running long enough to have entered the cycle. Of course the challenge has been constructed such that the clock is in the cycle or else the challenge wouldn't be solvable. No hint or justification of this has been provided to players as I felt doing so would give away the key solution idea. I considered many different options for avoiding this "issue" including shrinking the hash to 48 bits, or making the clock updated after 10ths or 100ths of a second, or stating that it had been running continuously since 1995 (about 1B seconds), etc. All of these came with flaws that I felt imbalanced the challenge in some way or another.
