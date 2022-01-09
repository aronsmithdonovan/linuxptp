#!/bin/bash
echo "pulling updated repo from GitHub..."
git pull
echo "fixing file timestamps..."
rm -f pre-send.txt
rm -f post-receive.txt
find . -type f -exec touch {} +
echo "compiling program..."
make clean
make ptp4l
echo "done."