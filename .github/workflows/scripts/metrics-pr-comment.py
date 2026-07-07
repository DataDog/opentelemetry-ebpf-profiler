#!/usr/bin/env python3
"""Diff two metrics.json files and build a GitHub PR comment.

Usage:
    metrics-pr-comment.py <before.json> <after.json>
"""

import json
import os
import sys

METRICS_URL = (
    "https://github.com/DataDog/opentelemetry-ebpf-profiler/"
    "blob/datadog/metrics/metrics.json"
)
DASHBOARD_URL = (
    "https://app.datadoghq.com/dashboard/zrz-tsd-42m/"
    "continuous-profiler-host-profiler-overview-synced"
    "?fromUser=false&refresh_mode=sliding"
    "&tab_id=69728643-8642-42fd-8a7c-737cf9a7fb28"
)
TEAM = "@datadog/profiling-full-host"
COMMENT_MARKER = "<!-- metrics-json-diff -->"


def load_metrics(path: str) -> set[str]:
    with open(path) as fh:
        defs = json.load(fh)

    names = set()
    for metric in defs:
        field = metric.get("field")
        if not field or metric.get("obsolete"):
            continue
        names.add(field.replace(".", "_"))
    return names


def set_output(name: str, value: str) -> None:
    gh_output = os.environ.get("GITHUB_OUTPUT")
    if gh_output:
        with open(gh_output, "a") as fh:
            fh.write(f"{name}<<EOF\n{value}\nEOF\n")
    else:
        sys.stdout.write(f"{name}={value}\n")


def build_comment(added: list[str], removed: list[str]) -> str:
    if not added and not removed:
        return (
            f"No active metric changes detected in [metrics.json]({METRICS_URL}).\n"
            "\n"
            f"{COMMENT_MARKER}"
        )

    diff_lines = []
    for name in added:
        diff_lines.append(f"+ {name}")
    for name in removed:
        diff_lines.append(f"- {name}")
    diff = "\n".join(diff_lines)

    return (
        f"{TEAM}\n"
        "\n"
        f"The following active metrics changed in [metrics.json]({METRICS_URL}):\n"
        "\n"
        "```diff\n"
        f"{diff}\n"
        "```\n"
        "\n"
        f"Please update the [Continuous Profiler Dashboard]({DASHBOARD_URL}) accordingly.\n"
        "\n"
        f"{COMMENT_MARKER}"
    )


def main() -> None:
    if len(sys.argv) != 3:
        sys.exit(f"usage: {sys.argv[0]} <before.json> <after.json>")

    before = load_metrics(sys.argv[1])
    after = load_metrics(sys.argv[2])
    added = sorted(after - before)
    removed = sorted(before - after)

    set_output("comment", build_comment(added, removed))


if __name__ == "__main__":
    main()
