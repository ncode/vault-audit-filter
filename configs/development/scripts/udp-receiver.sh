#!/bin/sh

set -x

dnf -y install nc

while true ; do
    nc -lu -p 9001
done

