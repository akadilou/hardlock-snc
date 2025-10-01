#!/usr/bin/env bash
set -euo pipefail
BR_MAIN=main
BR_CUR=$(git rev-parse --abbrev-ref HEAD)
echo "Latest runs (all):"
gh run list -L 10
echo
echo "Critical on ${BR_MAIN}:"
for WF in ci miri ".github/workflows/ffi.yml" guard-main fuzz geiger-report coverage unsafe-gate; do
  if gh workflow view "$WF" >/dev/null 2>&1; then
    gh run list --workflow "$WF" -b "$BR_MAIN" -L 1 --json name,displayTitle,status,conclusion,headBranch,url -q '.[].name + " | " + .displayTitle + " | " + .status + "/" + ( .conclusion // "none") + " | " + .headBranch + " | " + .url'
  fi
done
echo
echo "Critical on ${BR_CUR}:"
for WF in ci miri ".github/workflows/ffi.yml" guard-main fuzz geiger-report coverage unsafe-gate; do
  if gh workflow view "$WF" >/dev/null 2>&1; then
    gh run list --workflow "$WF" -b "$BR_CUR" -L 1 --json name,displayTitle,status,conclusion,headBranch,url -q '.[].name + " | " + .status + "/" + ( .conclusion // "none") + " | " + .headBranch + " | " + .url'
  fi
done
echo
echo "Failures (any branch):"
gh run list -L 20 --json conclusion,displayTitle,url -q '.[] | select(.conclusion=="failure") | .displayTitle + " => " + .url'
