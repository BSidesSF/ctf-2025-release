#!/usr/bin/env python3

import os
import time
import shutil
import re
import errno
import hashlib
from pathlib import Path
import datetime

DEBUG = False  # Set to False in production


def md5_trunc(input_bytes: bytes) -> bytes:
    if len(input_bytes) != 8:
        raise ValueError("Input must be exactly 8 bytes (64 bits).")

    # Compute MD5 hash
    md5_hash = hashlib.md5(input_bytes).digest()

    # Return the first 8 bytes (64 bits)
    return md5_hash[:8]


STATE_DIR = Path("state")
STATE_DIR.mkdir(exist_ok=True)

# Pre-compile the regular expression for numeric filenames
NUMERIC_FILENAME_RE = re.compile(r"^\d+$")

STATE_STR_RE = re.compile(r"^[a-f0-9]{16}$")


def get_latest_state(before_time: int):
    latest_time = None
    latest_file = None

    for file in STATE_DIR.iterdir():
        if file.is_file() and NUMERIC_FILENAME_RE.match(file.name):
            timestamp = int(file.name)
            if timestamp <= before_time:
                if latest_time is None or timestamp > latest_time:
                    latest_time = timestamp
                    latest_file = file

    if latest_file is not None:
        with latest_file.open("r") as f:
            state_hex = f.readline().rstrip("\n")
            return latest_time, bytes.fromhex(state_hex)
    else:
        raise ValueError("state directory is empty, or the clock is wrong")

def write_state(timestamp: int, state: str):
    temp_file = STATE_DIR / f".{timestamp}.tmp"
    final_file = STATE_DIR / str(timestamp)

    try:
        # Try to get exclusive access to the temp file for writing
        fd = os.open(temp_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
        with os.fdopen(fd, "w") as f:
            print(state.hex(), file=f)

        # Atomically move the temp file to final file
        try:
            temp_file.replace(final_file)  # os.replace is atomic on most filesystems
            if DEBUG:
                print(f"New state saved to: {final_file}")
        except Exception as e:
            if DEBUG:
                print(f"Error writing state file: {e}")

    except FileExistsError:
        if DEBUG:
            print(f"Another instance is already writing the state for timestamp {timestamp}, skipping.")
    except Exception as e:
        if DEBUG:
            print(f"Unexpected error while attempting to write state: {e}")


def update_state(past_time: int, past_state: bytes, goal_time: int) -> bytes:

    cstate = past_state
    for t in range(past_time + 1, goal_time + 1):
        cstate = md5_trunc(cstate)

        if t % 1000 == 0:
            if DEBUG:
                print(f"Writing state for {t} to {cstate.hex()}")
            write_state(t, cstate)

    return cstate

def get_cur_time_state() -> (int, bytes):
    # Get current UNIX time
    now = int(time.time())

    # Retrieve the latest state before now
    latest_state_time, state_data = get_latest_state(now)

    cstate = update_state(latest_state_time, state_data, now)


    if DEBUG:
        print(f"Got state for current time {now} of {cstate.hex()}")

    return now, cstate


with open("banner.txt") as banner:
    print(banner.read())

    now, cstate = get_cur_time_state()

    print("""
Welcome to the CERN time reversal experiment!

We have determined that quantum mechanics allows the arrow of time to
be reversed. It is simply statistical mechanics-- namely, entropy--
that make this unlikely.

We have devised a clever way around this issue! By generating enough
entropy going forward, the universe can be paid back its entropy debt
and time made to flow backwards. We do this by destroying 64 bits of
information to generate 64 new bits of information using a 1-way
function (truncated md5).

For example, if the current state is 0123456789abcdef then applying
truncated_md5(0123456789abcdef) = a1cd1d1fc6491068. Then the next
state would 3f8586d1de2385a3 and so forth.

Shortly after we turned on the machine we received a signal from the
future (see video). Unfortunately our detractors claim we could have
"fast-forwarded" the state when we turned the machine on and faked the
video.

This is where you come in! To prove that we can now reverse time use,
that video reverse the future state to present time. Since MD5 is
obviously super secure and can't ever be reversed, we're confident
this will be a convincing demonstration.
""")

    now_str = datetime.datetime.fromtimestamp(now, datetime.UTC).strftime('%Y-%m-%d %H:%M:%S')
    print(f"\n\nThe current time is {now_str} ({now}).")
    print("What is the current state? You have 30 seconds.\n")

    print("State = ? ", end="");

    in_str = input()

    # Be nice and clean up input
    in_str = in_str.strip()
    in_str = in_str.lower()

    new_now = int(time.time())

    if new_now - now > 30:
        print("You took too long!")
        exit(0)

    if re.match(STATE_STR_RE, in_str):
        if bytes.fromhex(in_str) == cstate:
            with open("flag.txt") as flag:
                print(flag.read())
                exit(0)

        else:
            print("That state was not correct. Remember, you have 30 seconds to reverse time.")
            exit(0)

    else:
        print("That is a not a well formatted state.")
        exit(0)
