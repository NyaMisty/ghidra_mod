# Upstream sync and branching

## 当前维护模型

`PATCH.md` 记录了当前维护约定：

- 主开发在 `mistypatch`。
- `mistypatch` 是源 patch line；上游更新后，应把保留的 `[mistypatch]` 提交重放到最新 `origin/master` 或 `origin/stable`。
- 为了保留原始 `CommitDate`，实际维护时按 `PATCH.md` 中的顺序 replay 流程重放提交。
- 历史上存在 AutoMerge CI 和手工 upstream merge，但它们是追上游记录，不应当作当前 patch line 的来源。
- commit message 必须以 `[mistypatch] ` 开头，便于从 upstream 合并提交中识别本地补丁。
- 2025-10-06 迁移记录：基于 upstream `53cca61f8c118702180abb90a21952e0b0b11ef4`，丢弃 `ezclone function inlining feature`，只保留 UI patches。

## 分支拓扑要点

当前仓库有多条 Misty 相关分支：

- `mistypatch`：当前工作分支，保留 UI patch 序列。
- `fork/master`：NyaMisty fork 的 master，通常承载把 `mistypatch` patch line 重放到 master 基点后的结果，也含历史 AutoMerge。
- `fork/stable`：NyaMisty fork 的 stable，通常承载把 `mistypatch` patch line或其 stable 子集重放到 stable 基点后的结果，也含历史 AutoMerge。
- `oldmod-10.3`：旧的 10.3 系列维护分支，包含早期 decompiler/loader 临时修改和 UI patch。
- `ezclone`：旧的反编译器 function inlining 改动分支，当前已按 `PATCH.md` 说明丢弃。

`mistypatch`、`fork/master`、`fork/stable` 上同一个功能经常有不同哈希，因为它们是 rebase/cherry-pick 到不同基点后的结果。判断功能是否存在时，应比较 subject、patch 内容和 touched files，不应只看 hash。

## AutoMerge CI

当前保留的 CI 文件：

- `.github/workflows/merge_remote.yml`
- `.github/workflows/merge_remote_stable.yml`

原始意图：
周期性把 NSA upstream 的 `master` 或 `stable` 合入 fork 的对应分支，减少本地 fork 长期落后的成本，并在冲突时尽早暴露。

当前定位：

- 这些 workflow 反映的是 fork 追上游历史，不是当前 Misty patch 维护 SOP。
- 当前补丁维护仍以 `mistypatch` 为源，具体流程统一以根目录 `PATCH.md` 为准。

实现方式：

- workflow 每 2 小时运行一次，也支持手动 `workflow_dispatch`。
- 设置 committer 为 `NyaMisty BuildWorker <gh-worker@misty.moe>`。
- checkout `LOCAL_BRANCH`，添加 upstream remote。
- 先执行 `git merge --no-commit --no-ff upstream/$UPSTREAM_BRANCH` 探测是否有新内容。
- 若没有变化，写 `updated=0` 并退出。
- 若有变化，写 `updated=1`。
- 如果最后一个提交是 `AutoMerge-*`，先 reset 掉旧 AutoMerge。
- 清理工作区后执行正式 merge，提交信息为 `AutoMerge-YYYYMMDD-HHMMSS`。
- 当 `updated=1` 时通过 `ad-m/github-push-action@master` force push 到 `LOCAL_BRANCH`。
- 最后调用 `NyaMisty/keepalive-workflow@master` 避免 scheduled workflow 失活。

历史迁移：

- 初始 CI：`4471b1cbeeaccfad6ec6b5edc24f188ca3fc6622`，作者 `NyaMisty <misty@misty.moe>`。
- 旧逻辑修复：`65aa8fafcce4db4e9302d981f8c3f80011c92f0e`，作者 `Sakuragawa Misty <gyc990326@gmail.com>`，主要改为每 2 小时同步、输出 `updated`、只在更新时 push、放宽 AutoMerge regex。
- 当前 `mistypatch` CI：`27329cc8ca8733b8274c60c7a47d7cb7d0fd2b0c`。
- 当前 `mistypatch` CI 修复：`ffaf35c69e1324a0388fb590bcadfeece1d08807`，把硬编码 `git checkout master` 改成 `git checkout $LOCAL_BRANCH`，并新增 stable workflow。
- `stable` 分支对应：`a89c05adfb878e22a0de962bd35332a92fe05e0a`、`eed56aadb277def9e82c13021e0d820f99ba8426`。

未来合并提示：

- 该 CI 会 force push，任何人工维护分支前要确认没有未推送或未备份的分支状态。
- `actions/checkout@v2` 和 `ad-m/github-push-action@master` 比较老，未来 GitHub Actions 环境升级时可能需要更新。
- CI 里出现 `git reset --hard` 和 `git clean -fd`，只应在 Actions 的临时 checkout 中使用，不要复制到本地工作区。
- 如果 AutoMerge 失败，workflow 当前只是打印 diff 并尝试 reset/clean，不会自动开 issue 或 PR；需要人工看 Actions log。

## AutoMerge 提交记录

在当前可见历史中，`NyaMisty BuildWorker <gh-worker@misty.moe>` 生成过这些同步提交：

- `5d53347e51525e97d650d0967a8ac9e062efc945` - `AutoMerge-20230217-233022`
- `1b209c7173a9a95fa06ab830626331acb44cef5a` - `AutoMerge-20230303-122728`
- `6b8c03ed48af526a9a4e0a5e8a707518ae13fd12` - `AutoMerge-20230309-141406`
- `9f21194af533345cea2c0ceb0ad2478c6fe05320` - `AutoMerge-20230314-123515`
- `65e6f72556c56eb63acdb44af240bbd418a41b9c` - `AutoMerge-20230407-122408`
- `3c70998c2fda529a2d699ba45c451d4187677baf` - `AutoMerge-20240131-221230`
- `82c09345e1f8bc23db57b8417fbac70af6d7f9c7` - `AutoMerge-20251112-221659` on `fork/master`
- `a6784f12772cd3bb6d6094807a17c69a8adc4764` - `AutoMerge-20260211-105220` on `fork/stable`

这些提交本身不是功能性 mod；它们表示 upstream 同步点。未来梳理功能差异时，应从 AutoMerge 合并提交中剥离 upstream 内容，只看已经进入历史的 `[mistypatch]` 提交和明确归档的历史分支提交。

## 历史上的手工 upstream merge 记录

- `c3178c708e0f1df368bcf8f75661c71b8be3e152` - 2026-05-27 在 `mistypatch` 手工合并 `origin/master`。
  - merge 前本地父提交：`e8ddb96f4bdd355f467c135b4753f41a89005859`。
  - merge 的 upstream 父提交：`94164bd6e90eef1ae6b771a5692c0ca53ea92b81`。
  - 冲突文件：`DetachedWindowNode.java`、`DockingWindowManager.java`、`KeyBindingsManager.java`。
  - 处理结论：保留 upstream 的 `org.jdom2.Element`、`placeholder.canTakeFocus()`、AltGraph key binding 支持，同时保留 Misty 的 Escape close、modal Location References 和 Meta/Ctrl 双注册。

该提交本身是 upstream 同步维护点，不是新的 Misty 功能补丁；当前常规维护流程仍以 `PATCH.md` 里的 patch replay 为准。
