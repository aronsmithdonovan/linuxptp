#!/bin/bash
echo "starting ptp4l..."
sudo date 010100001970
sudo ./ptp4l -i eth0 -m -s -S