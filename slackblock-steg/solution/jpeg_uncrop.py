#!/usr/bin/env python3

import io
import sys

def get_jpeg_dimensions(img_data):
    """
    Extract width and height from JPEG binary stream without using external libraries.
    """
    img_data.seek(0)  # Ensure we're at the start
    data = img_data.read()  # Read the binary data
    if data[:2] != b'\xFF\xD8':
        return True, "Not a valid JPEG file", 0, 0

    idx = 2  # Start after JPEG magic number

    while idx < len(data):
        # Find marker (0xFF followed by a non-FF byte)
        while data[idx] == 0xFF:
            idx += 1
        marker = data[idx]
        idx += 1

        # Stop at Start of Frame (SOF) markers that define image dimensions
        if 0xC0 <= marker <= 0xC2:  # Covers SOF0 (Baseline), SOF2 (Progressive), etc.
            height = int.from_bytes(data[idx+3:idx+5], 'big')
            width = int.from_bytes(data[idx+5:idx+7], 'big')


            return False, "", width, height

        # Skip the segment (Length field: next two bytes indicate size)
        segment_length = int.from_bytes(data[idx:idx+2], 'big')
        idx += segment_length

    return True, "Unable to find S0F segment with image dimensions", 0, 0


def set_jpeg_dimensions(img_data, wh):
    """
    Extract width and height from JPEG binary stream without using external libraries.
    """
    img_data.seek(0)  # Ensure we're at the start
    data = img_data.read()  # Read the binary data
    assert data[:2] == b'\xFF\xD8', "Not a valid JPEG file"

    idx = 2  # Start after JPEG magic number

    while idx < len(data):
        # Find marker (0xFF followed by a non-FF byte)
        while data[idx] == 0xFF:
            idx += 1
        marker = data[idx]
        idx += 1

        # Stop at Start of Frame (SOF) markers that define image dimensions
        if 0xC0 <= marker <= 0xC2:  # Covers SOF0 (Baseline), SOF2 (Progressive), etc.
            img_data.seek(idx + 3)
            img_data.write(wh[1].to_bytes(2, 'big'))
            img_data.write(wh[0].to_bytes(2, 'big'))

            return


        # Skip the segment (Length field: next two bytes indicate size)
        segment_length = int.from_bytes(data[idx:idx+2], 'big')
        idx += segment_length

    raise ValueError("No valid SOF marker found in JPEG file")


with open(sys.argv[1], "rb") as file:
    img_data = io.BytesIO(file.read())

iserr, errstr, width, height = get_jpeg_dimensions(img_data)
if iserr:
    print(f'Got error "{errstr}" with file "{sys.argv[1]}"')
    exit(0)

print(f"Width: {width}, Height: {height}")

nw = width
nh = height

if nw % 8 > 0:
    nw = ((width // 8) + 1) * 8

if nh % 8 > 0:
    nh = ((height // 8) + 1) * 8

if nw != width or nh != height:
    set_jpeg_dimensions(img_data, (nw, nh))

    with open('/tmp/uncrop.jpg', "wb") as out:
        img_data.seek(0)
        out.write(img_data.read())


