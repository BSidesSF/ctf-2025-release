#!/bin/bash

clang -o md5_brent -Wall -Wextra -O3 -march=native md5_brent.c -lcrypto -I /opt/homebrew/opt/openssl\@3.4/include/ -L /opt/homebrew/opt/openssl\@3.4/lib/
