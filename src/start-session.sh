#!/bin/sh

i=0
while true; do
    echo "$USER session... #$i"
    let i=$i+1
    sleep 30
done

exit 0
