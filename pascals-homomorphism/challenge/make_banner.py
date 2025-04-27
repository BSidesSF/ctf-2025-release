#!/usr/bin/env python3

H = 1 << 5
W = (H + 1) << 1

tri = [[" "] * W]

tri[0][W // 2] = "#"

print("".join(tri[0]))
for i in range(1, H):
    tri.append([" "] * W)
    for j in range(1, W - 1):
        if tri[i - 1][j - 1] != tri[i -1][j + 1]:
            tri[i][j] = "#"

    print("".join(tri[i]))

