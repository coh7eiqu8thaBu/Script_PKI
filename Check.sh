#!/bin/bash
for i in *.sh
do
  md5sum    -c $i.md5
done
