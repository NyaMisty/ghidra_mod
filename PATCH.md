# Ghidra Misty Patch

Patch are done in branch `mistypatch`, which is based on a good point

## Coding conventions

You must use commit message starting with `[mistypatch] ` to identify the commit is for mistypatch.

## Dev Workflow

1. We do the main development in branch `mistypatch`.
2. When a feature is done, we merge our branch from `mistypatch` to `master` and `stable`
3. The CI will automatically merge the upstream change to `master` and `stable`.
4. If there's any conflict, merge the `mistypatch` branch from master. If the conflict is too hard to resolve, rebase all the commit by rewriting the feature from scratch.

## Merge notes

### 2025-10-06
Dropped ezclone function inlining feature, keeping only ui patches