#!/usr/bin/env bash
# Creates the public repo under your account and pushes main. Requires an authenticated GitHub CLI.
set -euo pipefail
OWNER="JamestheBuildrCodes"; REPO="prompt-injection-attack-lab"

command -v gh >/dev/null || { echo "Install GitHub CLI: https://cli.github.com"; exit 1; }
gh auth status >/dev/null 2>&1 || { echo "Run: gh auth login"; exit 1; }

if gh repo view "$OWNER/$REPO" >/dev/null 2>&1; then
  echo "Repository $OWNER/$REPO already exists. Not overwriting. Inspect it first:"
  gh repo view "$OWNER/$REPO" --json url,pushedAt,defaultBranchRef
  exit 2
fi
[ -d .git ] || { git init -b main && git add -A && git commit -m "Initial commit: Prompt Injection Attack Lab"; }
gh repo create "$OWNER/$REPO" --public --source=. --remote=origin --push \
  --description "Local lab for testing LLM apps against prompt injection, jailbreaks and prompt leakage"
echo "Pushed to https://github.com/$OWNER/$REPO"
git ls-tree -r --name-only HEAD | wc -l | xargs echo "files committed:"
