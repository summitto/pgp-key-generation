#!/usr/bin/env bash

set -euo pipefail

if [[ $# -ge 1 && ($1 = "-h" || $1 = "--help") ]]; then
    echo >&2 "Usage: $0 [custom CMake arguments...]"
    echo >&2 "Will compile the application using the Clang static analyzer."
    echo >&2 "Any arguments to the script will be passed verbatim to CMake in addition to"
    echo >&2 "the arguments necessary for this script."
    exit 0
fi

sourcedir="$(dirname "$0")"
builddir="$(mktemp -d)"

trap "rm -rf '$builddir'" EXIT

nthreads="$(nproc || echo -n "")"
if [[ -z $nthreads ]]; then
    nthreads=4
    echo >&2 "Warning: Could not determine number of CPU cores, using $nthreads"
fi

CC=clang CXX=clang++ scan-build --use-cc=clang --use-c++=clang++ cmake -S "$sourcedir" -B "$builddir" -DCMAKE_BUILD_TYPE=Debug "$@"
scan-build --use-cc=clang --use-c++=clang++ make -j$(nproc) -C"$builddir"
