#!/usr/bin/env bash
set -euo pipefail
repo_root="$(git rev-parse --show-toplevel)"
# Scope hooks to this worktree; a sibling checkout keeps its original hooks.
git config extensions.worktreeConfig true
git config --worktree core.hooksPath "$repo_root/.githooks"
printf 'Installed hooks for %s\n' "$repo_root"
