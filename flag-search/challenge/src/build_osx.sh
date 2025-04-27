#!/bin/bash

clang -o flag-search -Wall -Wextra -O0 -g -march=native flag-search.c -lcrypto -I /opt/homebrew/opt/openssl\@3.4/include/ -L /opt/homebrew/opt/openssl\@3.4/lib/

