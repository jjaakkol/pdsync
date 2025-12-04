#!/bin/bash
dirsize=$(( 1024 * 1024 * 1024 ))  # 1 GiB
minsize=8192
umask 022

make_random_files() {
    local dir="$1"
    size="$2"
    [ -z "$dir" ] && { echo "Usage: make_random_dir <dirname>"; return 1; }
    mkdir -p "$dir"
    files=$(($dirsize / $size))
    echo "dir $dir creating $files files of size $size bytes"
    for i in $(seq 1 $files); do
        openssl rand $size > $dir/testfile-$i
        echo -n " [$size]"
    done
}

make_many_random_dirs() {
    local depth="$1"
    local i

    [ -z "$depth" ] && { echo "Usage: make_many_random_dirs <depth> [prefix]"; return 1; }
    [ "$depth" -le 0 ] && return

    for i in $(seq 13 30 ); do
        local dir="$2-$i-$depth"
        make_random_files "$dir" $(( 2**$i)) &
        make_many_random_dirs $((depth - 1)) "$dir/sub" $(( $depth-1 ))
    done
    wait
}

mkdir -p dsync-test && cd dsync-test && make_many_random_dirs 1 testdir
mkdir -p dsync-test/empty

