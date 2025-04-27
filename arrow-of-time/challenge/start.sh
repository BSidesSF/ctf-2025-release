#!/bin/bash

cd /app
ls
ls state

socat TCP-LISTEN:54321,reuseaddr,fork EXEC:'./arrow_of_time.py',stderr,pty
