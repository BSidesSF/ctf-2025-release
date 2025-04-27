#!/bin/bash

SRC_IP="172.24.20.31"
DST_IP="172.64.20.62"

NUM_PAIRS=50
# Use the script's process ID as the ICMP identifier for this run, ensure it
# fits within 16 bits for ICMP standard
ICMP_ID=$(($$ % 65536))

# Look to send request / reply pairs
for (( i=1; i<=$NUM_PAIRS; i++ )); do
    echo "[Pair $i/$NUM_PAIRS]"

    if [[ "$i" -eq 29 ]]; then
        nping --icmp --icmp-type 8 --icmp-code 0 \
        -c 1 \
        -S "$SRC_IP" \
        --icmp-id "$ICMP_ID" \
        --icmp-seq "$i" \
        --data-string "Q1RGe3kwdV91czNsM3NzX3IzcHQxbDN9" \
        "$DST_IP" \
        --quiet
    fi

    # Send ICMP Echo Request (Type 8)
    nping --icmp --icmp-type 8 --icmp-code 0 \
    -c 1 \
    -S "$SRC_IP" \
    --icmp-id "$ICMP_ID" \
    --icmp-seq "$i" \
    "$DST_IP" \
    --quiet

    sleep 0.1

    # Send ICMP Echo Reply (Type 0)
    nping --icmp --icmp-type 0 --icmp-code 0 \
    -c 1 \
    -S "$DST_IP" --icmp-id "$ICMP_ID" \
    --icmp-seq "$i" \
    "$SRC_IP" --quiet

    sleep 0.1

done
