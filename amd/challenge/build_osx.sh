#!/bin/bash

clang -o build_blob -Wall -Wextra -O3 -march=native build_blob.c -lcrypto -I /opt/homebrew/opt/openssl\@3.4/include/ -L /opt/homebrew/opt/openssl\@3.4/lib/
