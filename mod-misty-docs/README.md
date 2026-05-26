# Misty mod documentation

这个目录记录当前仓库里和 Misty/NyaMisty mod 相关的修改，目标是让以后继续追上游、重放补丁、判断是否要丢弃某个旧补丁时有依据可查。

## 证据范围

- 远端：`fork` 指向 `git@github.com:NyaMisty/ghidra_mod.git`，`origin` 指向 NSA upstream Ghidra。
- 当前开发分支：`mistypatch`。
- 当前保留的已提交补丁主要来自 `mistypatch` 这条源 patch line，以及重放到 `fork/master` 和 `fork/stable` 的等价 `[mistypatch]` 序列。
- 历史修改还包括 `oldmod-10.3`、`ezclone`、旧的 `master/stable` 衍生分支，以及由 `NyaMisty BuildWorker <gh-worker@misty.moe>` 生成的 AutoMerge 提交。

## 文档索引

- [current-ui-and-workflow-mods.md](current-ui-and-workflow-mods.md)：当前 `mistypatch` 保留的 UI/交互类补丁。
- [upstream-sync-and-branching.md](upstream-sync-and-branching.md)：分支维护方式、自动合并 CI、迁移流程。
- [historical-and-dropped-mods.md](historical-and-dropped-mods.md)：旧分支中出现过但当前已丢弃或被上游替代的修改。
- [commit-map.md](commit-map.md)：提交哈希、作者、分支对应关系和文件清单。
- [upstream-merge-checklist.md](upstream-merge-checklist.md)：以后追上游时的检查清单。

当前流程约定统一写在仓库根目录的 `PATCH.md`。本目录中的文件只保留证据、映射和检查项，不再单独维护 SOP。

## 状态分类

- `current-retained`：当前 `mistypatch`/`fork/master`/`fork/stable` 仍在携带的 Misty patch。
- `historical-dropped`：旧分支中存在，但 2025-10-06 迁移或更早维护过程中已经明确丢弃、回滚或被上游取代。
- `automation`：用于持续追上游的 GitHub Actions、分支策略和 AutoMerge 提交。

## 总体结论

当前保留的核心 mod 已从早期的反编译器深改收缩为一组 UI/工作流补丁：xref 弹窗模态化、快捷键系统改动、列表视图菜单去重、格式转换菜单去噪、Detached Window 的 Escape 关闭、Functions View 删除函数动作，以及自动追上游机制。`PATCH.md` 明确记录 2025-10-06 的迁移基点为 `53cca61f8c118702180abb90a21952e0b0b11ef4`，并说明已经丢弃 `ezclone function inlining feature`，只保留 UI patches。
