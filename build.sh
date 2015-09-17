#!/bin/bash

echo "Build Kernel..."
cp configs/linux-3.14.48-serverv-$1.config .config

make zImage -j12
echo "Build Kernel finished..."

echo "Build dts..."
make var-som-am33.dtb
echo "Build dts finished..."

