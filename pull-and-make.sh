#!/bin/bash
git pull
find . -type f -exec touch {} +
make clean
make ptp4l