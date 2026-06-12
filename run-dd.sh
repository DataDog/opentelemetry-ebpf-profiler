#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$repo_dir"

if systemctl is-active --quiet otel-ebpf-profiler.service 2>/dev/null; then
  echo "otel-ebpf-profiler.service is already running; stop it first to avoid two eBPF profilers fighting:" >&2
  echo "  sudo systemctl stop otel-ebpf-profiler.service" >&2
  exit 1
fi

if [[ -z "${DD_API_KEY:-}" ]]; then
  DD_API_KEY="$(sudo awk '/^api_key:/ {print $2; exit}' /etc/datadog-agent/datadog.yaml 2>/dev/null || true)"
fi
if [[ -z "${DD_SITE:-}" ]]; then
  DD_SITE="$(sudo awk '/^site:/ {print $2; exit}' /etc/datadog-agent/datadog.yaml 2>/dev/null || true)"
fi
DD_SITE="${DD_SITE:-datadoghq.com}"

if [[ -z "${DD_API_KEY:-}" ]]; then
  echo "DD_API_KEY is not set and could not be read from /etc/datadog-agent/datadog.yaml" >&2
  exit 1
fi

export DD_API_KEY DD_SITE

make otelcol-ebpf-profiler

exec sudo --preserve-env=DD_API_KEY,DD_SITE ./otelcol-ebpf-profiler \
  --feature-gates=+service.profilesSupport \
  --config ./datadog-intake.yaml
