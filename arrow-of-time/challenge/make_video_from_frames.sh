#!/bin/bash

ffmpeg -framerate 1 -pattern_type glob -i "/tmp/aclock_*.jpg" -c:v libx264 -r 30 out.mp4
