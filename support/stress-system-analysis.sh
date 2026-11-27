#!/usr/bin/env bash
# Runs TestSystemAnalysisStress in a QEMU guest, for chasing the sporadic
# unhandled system analysis request of multi-vCPU arm64 TCG guests.
# Usage: stress-system-analysis.sh <kernel-version> [requests]
# Expects support/tracer.test from `make integration-test-binaries`. Kernel
# lookup and QEMU options are those of run-tests.sh (KERN_DIR, QEMU_ARCH).

set -eu
set -o pipefail

kernel_version="${1:?expecting a kernel version}"
requests="${2:-20000}"

cd "$(dirname "${BASH_SOURCE[0]}")"
[ -x tracer.test ] || { echo "missing support/tracer.test" >&2; exit 1; }

case "${QEMU_ARCH:-$(uname -m)}" in
  x86_64) arch=amd64 ;;
  aarch64) arch=arm64 ;;
  *) echo "unsupported QEMU_ARCH" >&2; exit 1 ;;
esac

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
cp tracer.test "$work/"

bb_args=(-a "$arch" -o "$work/stress.cpio"
  -e "./tracer.test:-test.v -test.run=^TestSystemAnalysisStress$ -system-analysis-stress=${requests}")
if command -v bluebox >/dev/null; then
  (cd "$work" && bluebox "${bb_args[@]}")
else
  (cd "$work" && GOARCH= go run github.com/florianl/bluebox@v0.0.1 "${bb_args[@]}")
fi
echo tracer.test > "$work/stress.manifest"

./run-tests.sh --initramfs "$work/stress.cpio" "$kernel_version"
