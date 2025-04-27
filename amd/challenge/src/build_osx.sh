#!/bin/bash

clang -o amd -Wall -Wextra -O0 -g -march=native amd.c -lcrypto -I /opt/homebrew/opt/openssl\@3.4/include/ -L /opt/homebrew/opt/openssl\@3.4/lib/

