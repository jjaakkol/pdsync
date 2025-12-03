#!/bin/bash

umask 022

make_random_files() {
    local dir="$1"
    echo "random files for $dir"
    [ -z "$dir" ] && { echo "Usage: make_random_dir <dirname>"; return 1; }
    mkdir -p "$dir"
    for i in $(seq 001 512); do
        openssl rand 4096 > $dir/testfile-$i
    done
}

make_many_random_dirs() {
    local depth="$1"

    [ -z "$depth" ] && { echo "Usage: make_many_random_dirs <depth> [prefix]"; return 1; }
    [ "$depth" -le 0 ] && return

    for i in $(seq 1 16); do
        local dir="$2-$i-$depth"
        make_random_files "$dir" &
        make_many_random_dirs $((depth - 1)) "$dir/sub"
    done
    wait
}

mkdir -p dsync-test && cd dsync-test && make_many_random_dirs 2 testdir
mkdir -p dsync-test/empty

