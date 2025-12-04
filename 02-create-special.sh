#!/bin/bash
set -e

cd dsync-test
echo "This is a testdir for dir synchronization" > README.txt
mkdir -vp symlinks
( cd symlinks && ln -vfs ../*5* .)
mkdir -vp hardlinks
( cd hardlinks && ln -vf ../*14*/testfile*012* .)
rm  -v -f testfifo && mkfifo testfifo
echo Beginning. > sparsefile
truncate -s 1M sparsefile
echo This is the end. >> sparsefile
mkdir -p 0000 cant-read-this
mkdir -p chmod
for u in 4 6 7; do
  for g in {0..7}; do
    for o in {0..7}; do
      rm -f chmod/file-$u$g$o
      echo testing > chmod/file-$u$g$o
      chmod -v 0$u$g$o chmod/file-$u$g$o
    done
  done
done
rm -f chmod/noaccess
touch -m 000 chmod/noaccess
touch zerosizefile
mkdir emptydir

