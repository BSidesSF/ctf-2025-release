#!/bin/bash

socat TCP-LISTEN:55744,reuseaddr,fork EXEC:./block-cipher.pl
