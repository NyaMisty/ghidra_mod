# Historical and dropped mods

本文件记录旧分支中出现过，但当前 `mistypatch` 已不再保留的修改。它们仍然有价值，因为未来追上游时可能再次遇到相同问题，或者需要判断某个补丁是否应该复活。

## 1. Decompiler ezclone/function inlining 系列

状态：`historical-dropped`

来源：

- 主要作者显示为 `homes410 <homes410@users.noreply.github.com>`。
- 由 `NyaMisty <misty@misty.moe>` 在 `ezclone` 分支中提交/携带。
- `PATCH.md` 在 2025-10-06 明确写到：`Dropped ezclone function inlining feature, keeping only ui patches`。

原始意图：
扩展 Ghidra decompiler 的 EZ inline/flow clone 行为，使更多函数可以被 inline，并在 inline 后修正分支、return、override 等 p-code 关系。该系列属于反编译器 C++ 核心深改，不是 UI patch。

主要实现方式：

- 修改 `Ghidra/Features/Decompiler/src/decompile/cpp/flow.cc` 和 `flow.hh`。
- 把 `FlowInfo::inlineEZClone` 的参数从固定 `Address calladdr` 改为 `PcodeOp *&callop`，以便围绕真实 call op 和后继 op 重写 p-code。
- inline 时建立旧地址到新 `SeqNum` 的映射，用于重写 cloned branch/cbranch 的相对目标。
- 遇到 `CPUI_RETURN` 时，不再简单停止，而是在可行情况下生成跳回 fallthrough 的 `CPUI_BRANCH`。
- 对 cloned branch/cbranch 收集 worklist，后续把 code-space input 改成相对常量或对应目标。
- `checkEZModel` 的定义从“无 call/branch 的 straight-line leaf”放宽为更偏向“没有 noreturn/跳表等不可处理情况”的模型。
- 后续补丁通过 `visited` map 处理目标地址落在指令范围内但不等于指令起始地址的情况。
- 再后续补丁记录 `ezflow_inline_recursion`，避免 inline 后的 p-code 被 indirect/prototype override 再次改写，防止无限循环。

相关提交：

- `76d115d87ecda5120688cfd023046bced86a5339` - `220805-decompiler-ezclone`
- `fe9634b81d4c9d717cd23a693f4927c57f8522cc` - `220807-decompiler-ezclone-2`
- `23afcaa93fff69fda3b68f6a3c7ab956c6f5241b` - `220810-decompiler-ezclone-3`
- `f8306457cb568abf37a6fb058040529463ead81d` - `220817-decompiler-ezclone-4`
- `6248352d28155a7f853fc3ceccfa1a273d619ffc` - `230127-flow-ezinline-disallowoverride-Ghidra_10.2_build`
- `98eb4f8efb7c0313ffecef6cb8abb694adf789e0` - `Add missing tuple includes`

`98eb4f8...` 的特殊点：

- 它由 `NyaMisty <misty@misty.moe>` 直接提交。
- 只补了 `#include <tuple>`，并把 `tuple<PcodeOp*, uint4>` 调整为 `std::tuple<PcodeOp*, uint4>`。
- 该提交的存在依赖 ezclone 系列中的 `inlineEZClone` worklist 代码；当前 UI-only `mistypatch` 不再需要它。

未来合并提示：

- 不要在追上游时无意中把 ezclone 系列带回当前 `mistypatch`，除非明确决定恢复反编译器深改。
- 若要恢复，必须重新基于当前 upstream 的 `flow.cc/flow.hh` 设计，不能直接 cherry-pick 旧补丁。
- 重点比较 upstream 后续 inlining 相关修复，例如 `GP-3499 InlineFunctionHang`、`GP-5832 InlineOpTarget` 等，避免重复解决已上游化的问题。
- 该系列影响 decompiler correctness，恢复时需要 decompiler regression tests 和真实样本验证。

## 2. Decompiler 中 Edit Function Signature 的启用条件

状态：`historical-dropped`

原始意图：
限制 Decompiler 右键菜单里的 `"Edit Function Signature"`，避免在任意位置都允许编辑函数签名。注释中写明不使用 `getFunction(Function function, DecompilerActionContext context)`，因为它会允许到处改变函数签名。

实现方式：

- 修改 `Ghidra/Features/Decompiler/src/main/java/ghidra/app/plugin/core/decompile/actions/SpecifyCPrototypeAction.java`。
- `isEnabledForDecompilerContext` 中原本返回 `getFunction(function, context) != null`。
- 补丁改为返回 `getFunction(context) != null`。

相关提交：

- `65106a7f43a7ec3a33a784bad9f30595301213fd` - `Change "Edit Function Signature" enable case in decompiler`

迁移状态：

- 该补丁存在于旧历史，但当前 `origin/master...mistypatch` 的保留补丁文件清单中没有 `SpecifyCPrototypeAction.java`。
- 当前文档把它归类为已丢弃/未迁移的历史 UI 行为。

未来合并提示：

- 如果用户再次遇到 decompiler 中函数签名编辑入口过宽的问题，可以先检查 upstream 当前 `SpecifyCPrototypeAction` 的行为，再决定是否恢复这个小补丁。

## 3. Mach-O DYLD chained pointer 临时修复

状态：`historical-dropped`

原始意图：
临时修复 Mach-O `PTR_64 DYLD Chained Fixup` 地址计算问题，避免对不该加 image base offset 的 pointer format 也加 offset。

实现方式：

- 修改 `Ghidra/Features/Base/src/main/java/ghidra/app/util/opinion/MachoProgramBuilder.java`。
- 原逻辑对 `DyldChainedPtr.getTarget(...)` 的结果无条件 `newChainValue += imageBaseOffset`。
- 补丁改为仅当 `pointerFormat == DyldChainType.DYLD_CHAINED_PTR_64_OFFSET` 时加 `imageBaseOffset`。

相关提交：

- `013d0aad5ae78672dadc49269b68a859fd3524d0` - `Temp fix for PTR_64 DYLD Chained Fixup`
- `8bd98c99d35b1eceebcd8e44785dba3a6eadfc7a` - `Revert custom fix PTR_64 DYLD Chained Fixup to accept upstream fix`

迁移状态：

- 已被明确 revert，理由是接受 upstream fix。
- 当前 `mistypatch` 不应携带该补丁。

未来合并提示：

- 如果 Mach-O chained fixup 再次出问题，先查 upstream 对 `MachoProgramBuilder` 和 `DyldChainedPtr` 的当前实现。
- 不要直接恢复 `013d0a...`，因为它已经被作者自己标记为临时修复并回滚。

## 4. ManualMerge-230419

状态：`automation/history`

相关提交：

- `9b10c9b7e5c6c22598571a26eae2723452575809` - `ManualMerge-230419`

说明：

这是一次大规模手工合并 upstream 的 merge commit，涉及几百个文件。它不是一个独立功能 mod。梳理 Misty 修改时应把它视为上游同步历史，而不是把其中的大量 upstream 文件差异归到 Misty 功能下。

未来合并提示：

- 遇到大型 merge commit 时，用 first-parent 历史和 `[mistypatch]` 前缀区分本地功能补丁。
- 对旧分支做差异分析时，不要直接把 `oldmod-10.3` 对 upstream 的全量 diff 当成功能列表。
