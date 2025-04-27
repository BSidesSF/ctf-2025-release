#!/bin/bash

find /home/bmenrigh/projects/github/ctf-2025/challenges/matryoshkafs/challenge/fragment_files/ -type f | sort -R | xargs -I '{}' cp '{}' .

ls -1 *.* | egrep -v '32' | xargs rm
