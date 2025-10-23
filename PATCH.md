# Ghidra Misty Patch

Patch are done in branch `mistypatch`, which is based on a good point

## Coding conventions

You must use commit message starting with `[mistypatch] ` to identify the commit is for mistypatch.

## Dev Workflow

1. We do the main development in branch `mistypatch`.
2. When a feature is done, we REBASE our branch from `mistypatch` to `master` and `stable`
3. The CI will automatically merge the upstream change to `master` and `stable`.
4. If there's any conflict, REBASE the `mistypatch` branch from master.
   - `git rebase --onto 'stable|master' BASE_COMMIT_ID mistypatch~0`
   - `git branch -f 'stable|master'`
   - Record the new upstream base commit ID.
5. If the conflict is too hard to resolve, rebase all the commit by rewriting the feature from scratch.

## Merge notes

### 2025-10-06
Based on 53cca61f8c118702180abb90a21952e0b0b11ef4
Dropped ezclone function inlining feature, keeping only ui patches