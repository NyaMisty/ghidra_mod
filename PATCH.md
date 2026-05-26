# Ghidra Misty Patch

Patches are maintained in branch `mistypatch`.

## Coding conventions

You must use commit messages starting with `[mistypatch] ` to identify commits that belong to the Misty patch line.

## Dev workflow

1. Do the main development in branch `mistypatch`.
2. Treat `mistypatch` as the source patch line. When upstream moves, do not use a new upstream merge commit as the normal maintenance path.
3. Instead, replay the retained `[mistypatch]` commits onto the latest `origin/master` or `origin/stable`.
4. Record the old upstream base before replay:
   - `git merge-base mistypatch origin/master`
   - Or the corresponding stable base when replaying to `origin/stable`.
5. In this repository, "rebase while preserving commit dates" means replaying the commit range onto the new upstream while restoring each commit's original `AuthorDate` and `CommitDate`.
   - Plain `git rebase` rewrites `CommitDate`.
   - Use ordered replay with original metadata when commit dates must stay unchanged.
6. Recommended PowerShell flow for replaying a contiguous patch line to the latest upstream:
   - `git fetch --all --prune`
   - `git checkout -B mistypatch-replay origin/master`
   - `$commits = git log --reverse --first-parent --format="%H" OLD_BASE..mistypatch`
   - `foreach ($c in $commits) {`
   - `  $env:GIT_AUTHOR_DATE = git show -s --format=%aI $c`
   - `  $env:GIT_COMMITTER_DATE = git show -s --format=%cI $c`
   - `  git cherry-pick $c`
   - `  if ($LASTEXITCODE -ne 0) { break }`
   - `}`
   - `Remove-Item Env:GIT_AUTHOR_DATE -ErrorAction Ignore`
   - `Remove-Item Env:GIT_COMMITTER_DATE -ErrorAction Ignore`
7. After `mistypatch` is rebuilt, sync local `master` and `stable` from it:
   - `master` should carry the same retained patch line on top of the latest `origin/master`.
   - `stable` should replay the retained patch line, or the intended stable subset, on top of the latest `origin/stable`.
   - Preserve original dates there as well.
8. Resolve conflicts against the latest upstream carefully. Keep intended Misty behavior, drop already-upstreamed logic, and do not resurrect intentionally dropped patches.
9. If a conflict is too hard to resolve safely, rewrite the affected feature on top of the new upstream instead of forcing a bad replay.

## Documentation

`PATCH.md` is the only workflow/SOP document for maintaining Misty patches.

When the retained patch line, branch mapping, upstream status, or dropped patches change, update the relevant reference docs in `mod-misty-docs`:

- `mod-misty-docs/README.md`
- `mod-misty-docs/current-ui-and-workflow-mods.md`
- `mod-misty-docs/historical-and-dropped-mods.md`
- `mod-misty-docs/upstream-sync-and-branching.md`
- `mod-misty-docs/commit-map.md`
- `mod-misty-docs/upstream-merge-checklist.md`

Those files are reference material only. Do not create or maintain a separate SOP file for upstream sync.

## Related docs

- `mod-misty-docs/README.md`: index and scope
- `mod-misty-docs/current-ui-and-workflow-mods.md`: retained features
- `mod-misty-docs/historical-and-dropped-mods.md`: intentionally dropped or upstreamed history
- `mod-misty-docs/upstream-sync-and-branching.md`: branch topology and historical sync records
- `mod-misty-docs/commit-map.md`: commit equivalence across branches
- `mod-misty-docs/upstream-merge-checklist.md`: replay checklist for future upstream updates

## Upstream base notes

### 2025-10-06
Based on 53cca61f8c118702180abb90a21952e0b0b11ef4
Dropped ezclone function inlining feature, keeping only ui patches
