#!/usr/bin/env bash
set -euo pipefail

BR="sdk-tests-readd"
WF_PATH=".github/workflows/sdk-tests.yml"

git push -u origin "$BR"

if ! gh pr view "$BR" >/dev/null 2>&1; then
  gh pr create --fill --base main --head "$BR"
fi

gh pr checks "$BR" || true
gh pr merge --squash --delete-branch "$BR"

gh workflow run "$WF_PATH" -r main

RID="$(gh run list --workflow "$WF_PATH" -b main -L 1 --json databaseId -q '.[0].databaseId')"
if [ -z "${RID:-}" ]; then
  echo "Aucun run détecté pour $WF_PATH sur main"; exit 3
fi

gh run watch "$RID" --exit-status

echo "Résumé des jobs sdk-tests:"
gh run view "$RID" --json jobs -q '.jobs[] | .name + " => " + (.conclusion // "none")'

echo "URL du run:"
gh run view "$RID" --json url -q .url
