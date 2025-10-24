#!/usr/bin/env bash
set -euo pipefail

MSG="${1:-"chore: update"}"
BRANCH="auto-$(date +%Y%m%d-%H%M%S)"

# 1. Créer une branche unique
git checkout -b "$BRANCH"

# 2. Ajouter tous les changements et commit
git add .
git commit -m "$MSG" || echo "⚠️ Rien à commit (working tree clean)."

# 3. Pousser la branche
git push -u origin "$BRANCH"

# 4. Créer une PR vers main
gh pr create --fill --base main --head "$BRANCH" || true

# 5. Lancer les checks CI
gh pr checks "$BRANCH" || true

echo "✅ Branche $BRANCH poussée et PR créée."
echo "ℹ️ Quand la CI est verte, merge avec:"
echo "   gh pr merge --squash --delete-branch $BRANCH"
