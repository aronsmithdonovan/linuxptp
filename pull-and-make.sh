#!/bin/bash
git pull
rm -f pre-send.txt
rm -f post-receive.txt
find . -type f -exec touch {} +
make clean
make ptp4l