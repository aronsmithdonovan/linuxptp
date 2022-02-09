#!/bin/bash
git pull
make clean
find . -type f -exec touch {} +
chmod +x l_run.sh
chmod +x f_run.sh
chmod +x setup.sh
make ptp4l