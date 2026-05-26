# Commit map

本文件把功能主题、提交哈希、作者和分支对应关系列在一起。由于这些补丁多次 rebase/cherry-pick，同一功能在不同分支上可能有不同 hash。

## 当前保留补丁序列

| 功能 | mistypatch / fork-master 系列 | fork-stable 系列 | 作者 | 主要文件 |
| --- | --- | --- | --- | --- |
| Listing 变量操作数不启用 Edit Label | `340ba07f4ff1c865a8207965dfa60b514af0043a` | `8e7313efb5c2415e6ec2f2431c0e129227cafaa8` | NyaMisty | `EditLabelAction.java` |
| Location References 模态化 | `51a30a33823f5585c75b88d2837ec7de207d1bc4` | `25ee4da9ac4bd9a7a734852e7bd1b69f36887589` | Misty | `LocationReferencesPanel.java`, `LocationReferencesProvider.java`, `GoToServiceWrap.java`, Docking files |
| Shared action 快捷键可修改 | `76368d9078892c699f1541931291900ce32364a5` | `662d6279c5e34676f7cbe2d1d192d671cf68e1a2` | Misty | `KeyBindingUtils.java` |
| Meta/Ctrl 快捷键互映射 | `6a5283b67ce92ade90b2802ca3dc21de5fcd8c77` | `81edd9734cb486a12677169c11ce42a13301b75a` | Misty | `KeyBindingsManager.java`, `KeyBindingUtils.java`, `KeyBindings.java` |
| ConvertAction 相同格式不启用 | `aa9499fc53a8b02e0bfa54d120a18f6275ec0a21` | `1ac81a35ac44a4b7bbed2c1e21f31d211a7389a6` | Misty | `AbstractConvertAction.java` |
| Detached Window Escape 关闭 | `cd7e1ddbd827544da1fce75b404c919a5be56eaa` | `70e2feb833f1fb349010aed1b0a7a2bbb4705a62` | Misty | `DetachedWindowNode.java` |
| 2025 迁移适配 | `7081580c919622fc40ec105edd2f54b82693d026` | `1634aef4f4b90b3cc454ec33cfee907ba175c5d5` | Misty | `NextPrevAddressPlugin.java`, `LocationReferencesPanel.java`, keybinding imports |
| AutoMerge CI | `27329cc8ca8733b8274c60c7a47d7cb7d0fd2b0c` | `a89c05adfb878e22a0de962bd35332a92fe05e0a` | Misty | `.github/workflows/merge_remote.yml` |
| AutoMerge CI branch 修复和 stable workflow | `ffaf35c69e1324a0388fb590bcadfeece1d08807` | `eed56aadb277def9e82c13021e0d820f99ba8426` | Misty | `.github/workflows/merge_remote.yml`, `.github/workflows/merge_remote_stable.yml` |
| 开发/迁移说明 | `b50b361f555c4318ba1023682eeb2d271bd68d2d` on `mistypatch`, `cb79ce4bd5146bd8f8ffdf6f78935f5dfcf3bbfd` on `fork/master` | `abc449f8b9afce647bd43dff10ae778e722ebcd0` | Misty | `PATCH.md` |
| Functions View 删除函数 | `534c6bd3f85c001f790f052cd60dea205eba5e89` on `mistypatch` | none seen | Misty | `DeleteFunctionAction.java`, `FunctionPlugin.java` |

## 旧分支中的原始或等价提交

| 功能 | 旧提交 | 作者 | 状态 |
| --- | --- | --- | --- |
| Listing 变量操作数不启用 Edit Label | `d2639e365e025d8f7bbca7a8884e1145e1b1e3a1` | NyaMisty | 后续重放到当前分支 |
| Listing 变量操作数不启用 Edit Label | `670f3332cb3c809f71293fb24a78b055791a317b` | NyaMisty | 等价重放版本 |
| Listing 变量操作数不启用 Edit Label | `0e13f0435f0a29e73459c4b18b7886ec6c6a86d3` | NyaMisty | 等价重放版本 |
| Edit Function Signature 启用条件 | `65106a7f43a7ec3a33a784bad9f30595301213fd` | NyaMisty | 历史补丁，当前未保留 |
| 初始 AutoMerge CI | `4471b1cbeeaccfad6ec6b5edc24f188ca3fc6622` | NyaMisty | 后续被当前 CI 替代 |
| AutoMerge 逻辑修复 | `65aa8fafcce4db4e9302d981f8c3f80011c92f0e` | Sakuragawa Misty | 思路进入当前 CI |
| DYLD chained pointer 临时修复 | `013d0aad5ae78672dadc49269b68a859fd3524d0` | Misty | 已回滚 |
| DYLD chained pointer 回滚 | `8bd98c99d35b1eceebcd8e44785dba3a6eadfc7a` | Misty | 接受 upstream fix |
| oldmod 手工合并 upstream | `9b10c9b7e5c6c22598571a26eae2723452575809` | Misty | merge history，不是功能 mod |

## `git log --author="^NyaMisty"` 覆盖审计

直接作者名以 `NyaMisty` 开头的提交在当前 repo 中分为三类：

- 功能提交：`98eb4f8efb7c0313ffecef6cb8abb694adf789e0`、`65106a7f43a7ec3a33a784bad9f30595301213fd`、`4471b1cbeeaccfad6ec6b5edc24f188ca3fc6622`、`d2639e365e025d8f7bbca7a8884e1145e1b1e3a1`、`670f3332cb3c809f71293fb24a78b055791a317b`、`0e13f0435f0a29e73459c4b18b7886ec6c6a86d3`、`340ba07f4ff1c865a8207965dfa60b514af0043a`、`8e7313efb5c2415e6ec2f2431c0e129227cafaa8`。
- 自动合并提交：`5d53347e51525e97d650d0967a8ac9e062efc945`、`1b209c7173a9a95fa06ab830626331acb44cef5a`、`6b8c03ed48af526a9a4e0a5e8a707518ae13fd12`、`9f21194af533345cea2c0ceb0ad2478c6fe05320`、`65e6f72556c56eb63acdb44af240bbd418a41b9c`、`3c70998c2fda529a2d699ba45c451d4187677baf`、`82c09345e1f8bc23db57b8417fbac70af6d7f9c7`、`a6784f12772cd3bb6d6094807a17c69a8adc4764`。
- 功能上等价但跨分支重放的提交已经在上表按功能归并；AutoMerge 只作为维护历史记录，不作为独立 mod 功能。

## 其他 Misty 归档重放提交

这些提交也由 `Misty <gyc990326@gmail.com>` 或相关身份提交，但不在当前 `mistypatch` 主线。它们是同一组 UI patch 在旧 tag、旧列表分支或 stash 中的等价重放版本。

| 归档 ref / 上下文 | 提交 | 对应功能 | 说明 |
| --- | --- | --- | --- |
| `tag: v11.4.2-mod1` | `f1e44f454d64db05a08aa841f1122268ce629fa7` | 2025 迁移适配 | 等价于当前 `7081580...` / stable `1634aef...` |
| `tag: v11.4.2-mod1` | `1ab28a1272293c325564d896bd4e330269b78dc7` | AutoMerge CI | 等价于当前 `27329c...` / stable `a89c05...` |
| `tag: v11.4.2-mod1` | `371e78c9b68a5824b68869b9316033ea29307e2a` | Detached Window Escape 关闭 | 等价于当前 `cd7e1d...` / stable `70e2fe...` |
| `tag: v11.4.2-mod1` | `3c58248e886cf696c80a767dd6d090f42010c922` | ConvertAction 相同格式不启用 | 等价于当前 `aa9499...` / stable `1ac81a...` |
| `tag: v11.4.2-mod1` | `8dce8e3136962cc4b28a9e883d2b6e9ed18f88bf` | Meta/Ctrl 快捷键互映射 | 等价于当前 `6a5283...` / stable `81edd9...` |
| `tag: v11.4.2-mod1` | `0122032992202338fff06e3f047ff17899c5cc9d` | Shared action 快捷键可修改 | 等价于当前 `76368d...` / stable `662d62...` |
| `tag: v11.4.2-mod1` | `8ba76aa43f7cf3c3532836951372c01ab2a8c132` | Location References 模态化 | 等价于当前 `51a30a...` / stable `25ee4d...` |
| `tag: list` | `b1c1a491a70c25272b8b253dc2f5818e445a8c14` | 2025 迁移适配 | 旧列表/uipatch 归档版本 |
| `tag: list` | `02029b66692e4b5ea3153cf797355a196d0d3c90` | AutoMerge CI | 旧列表/uipatch 归档版本 |
| `tag: list` | `2812add4b493c1342c1bee09f2c8e4c966432679` | Detached Window Escape 关闭 | 旧列表/uipatch 归档版本 |
| `tag: list` | `70b8133cc553f1840119205dd4eb2eebde0f8ea4` | ConvertAction 相同格式不启用 | 旧列表/uipatch 归档版本 |
| `tag: list` | `b6cf303a995f948cef2330bf7b220c88febf71df` | Meta/Ctrl 快捷键互映射 | 旧列表/uipatch 归档版本 |
| `tag: list` | `da0d4788edd161eb20a08ac05accaad1ee908ae2` | Shared action 快捷键可修改 | 旧列表/uipatch 归档版本 |
| `tag: list` | `c860f0712175e12afb4f296420c3167b3dbd751c` | Location References 模态化 | 旧列表/uipatch 归档版本 |
| `refs/stash` base | `8a523ebb61f6bf036f4690a31380266d62eb012f` | Location References 模态化早期状态 | stash 基点，曾额外涉及 `.gitignore` 和 `KeyBindingsPanel.java` |
| `refs/stash` index | `08787260eb8bdbb26cdaa784008365d2adf4bacc` | Location References 模态化暂存状态 | stash 的 index parent，不是独立功能 |
| `refs/stash` working state | `4dbabc414901319cd1b8e54be35ccd0c68edde34` | Location References 模态化临时状态 | `refs/stash` merge commit，不是当前保留补丁 |

## 当前新增提交

这个提交是在 2026-05-27 重新审计时出现在当前 `mistypatch` 历史中的新 `[mistypatch]` 提交：

- `534c6bd3f85c001f790f052cd60dea205eba5e89`：位于 `mistypatch`，新增 Functions View 删除函数动作。

## ezclone / decompiler 深改提交

| 提交 | 作者 / committer | 主题 | 当前状态 |
| --- | --- | --- | --- |
| `76d115d87ecda5120688cfd023046bced86a5339` | homes410 / NyaMisty | `220805-decompiler-ezclone` | historical-dropped |
| `fe9634b81d4c9d717cd23a693f4927c57f8522cc` | homes410 / NyaMisty | `220807-decompiler-ezclone-2` | historical-dropped |
| `23afcaa93fff69fda3b68f6a3c7ab956c6f5241b` | homes410 / NyaMisty | `220810-decompiler-ezclone-3` | historical-dropped |
| `f8306457cb568abf37a6fb058040529463ead81d` | homes410 / NyaMisty | `220817-decompiler-ezclone-4` | historical-dropped |
| `6248352d28155a7f853fc3ceccfa1a273d619ffc` | homes410 / NyaMisty | `230127-flow-ezinline-disallowoverride-Ghidra_10.2_build` | historical-dropped |
| `98eb4f8efb7c0313ffecef6cb8abb694adf789e0` | NyaMisty | `Add missing tuple includes` | historical-dropped, tied to ezclone |

## AutoMerge 提交

| 提交 | 日期 | 分支/上下文 | 说明 |
| --- | --- | --- | --- |
| `5d53347e51525e97d650d0967a8ac9e062efc945` | 2023-02-17 | old history | `AutoMerge-20230217-233022` |
| `1b209c7173a9a95fa06ab830626331acb44cef5a` | 2023-03-03 | old history | `AutoMerge-20230303-122728` |
| `6b8c03ed48af526a9a4e0a5e8a707518ae13fd12` | 2023-03-09 | old history | `AutoMerge-20230309-141406` |
| `9f21194af533345cea2c0ceb0ad2478c6fe05320` | 2023-03-14 | old history | `AutoMerge-20230314-123515` |
| `65e6f72556c56eb63acdb44af240bbd418a41b9c` | 2023-04-07 | old history | `AutoMerge-20230407-122408` |
| `3c70998c2fda529a2d699ba45c451d4187677baf` | 2024-01-31 | old history | `AutoMerge-20240131-221230` |
| `82c09345e1f8bc23db57b8417fbac70af6d7f9c7` | 2025-11-12 | `fork/master` | `AutoMerge-20251112-221659` |
| `a6784f12772cd3bb6d6094807a17c69a8adc4764` | 2026-02-11 | `fork/stable` | `AutoMerge-20260211-105220` |
