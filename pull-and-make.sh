#!/bin/bash
git pull
make clean
find . -type f -exec touch {} +
make ptp4l