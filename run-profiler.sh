#!/usr/bin/env bash
set -euo pipefail

make

sudo ./ebpf-profiler \
  -collection-agent=127.0.0.1:4317 \
  -disable-tls \
  -heap-profiling \
  -verbose
