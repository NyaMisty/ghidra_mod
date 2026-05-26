# Upstream replay checklist

文件名沿用历史命名；当前这份清单用于把 Misty patch 重放到新的 upstream Ghidra 版本时使用。具体流程以仓库根目录 `PATCH.md` 为准，这里只保留检查项。

## 1. 先确认范围

- 记录当前 upstream base：`git merge-base mistypatch origin/master` 或对应 stable base。
- 列出本地功能提交：`git log --format="%H %an <%ae> %s" <base>..mistypatch`。
- 只把已经进入历史的 `[mistypatch]` 提交和明确归档的历史分支提交当作本地功能；不要把 AutoMerge、大型 upstream merge 或当前未提交工作区改动当作功能补丁。
- 检查 `PATCH.md` 是否有新的迁移说明。

## 2. 当前保留 UI patch 的逐项验证

- `EditLabelAction.java`：Listing 变量操作数字段不显示 `Edit Label`。
- `LocationReferencesPanel.java` / `LocationReferencesProvider.java` / Docking files：xref 结果窗口是单选、模态、Escape 关闭、跳转后关闭。
- `GoToServiceWrap.java`：若 upstream `GoToService` 新增方法，wrapper 必须同步实现。
- `KeyBindingUtils.java`：shared action 仍进入 key binding 列表，但 system action 不被暴露。
- `KeyBindingsManager.java` / `KeyBindingsModel.java`：Meta/Ctrl 双注册和保存规范化仍工作。
- `AbstractConvertAction.java`：当前格式和目标格式相同的 convert action 不启用。
- `DetachedWindowNode.java` / `NextPrevAddressPlugin.java`：Detached window 中 Escape 不会同时触发主窗口导航。
- `DeleteFunctionAction.java` / `FunctionPlugin.java`：Functions View 下 Delete action 可用，Listing 下不重复启用。

## 3. 2026-05-27 已知冲突模式

- `DetachedWindowNode.java`：upstream 当前使用 `org.jdom2.Element`。冲突时保留该 import，同时保留 Misty 的 `KeyBindingUtils` import、`installEscapeAction()`、`isForceModal(...)`、modal `JDialog` 和 delayed `setVisible(true)`。
- `DockingWindowManager.java`：`movePlaceholderToFront(...)` 要先保留 upstream 的 `placeholder.canTakeFocus()` guard，再执行 `placeholder.toFront()` 和 Misty modal `JDialog` 的 `SwingUtilities.invokeLater(() -> toFront(window))`。
- `KeyBindingsManager.java`：upstream AltGraph 支持必须和 Misty Meta/Ctrl 双注册共存。保留 `fixupAltGraphKeyStrokeMapping(...)`、`maybeGenerateAltGraphKeyStroke(...)`、remove path 中的 AltGraph 清理，并让 AltGraph 生成的 stroke 继续调用 Misty 的四参数 `doAddKeyBinding(...)`。
- `KeyBindingsModel.java`：当前 upstream 中保存快捷键的模型文件是 `KeyBindingsModel.java`；旧文档里出现的 `KeyBindings.java` 不再是当前文件名。

## 4. 历史补丁不要误带回

- 不要自动恢复 `ezclone` / `inlineEZClone` C++ 系列，除非明确要重新维护反编译器深改。
- 不要恢复 `013d0a...` 的 Mach-O DYLD chained pointer 临时修复，它已经被回滚以接受 upstream fix。
- 不要把 `ManualMerge-230419` 的大 diff 当作 Misty 功能。
- `SpecifyCPrototypeAction.java` 的 decompiler 签名编辑启用条件是历史补丁，当前未保留；只有用户明确需要时才重新评估。

## 5. 推荐命令

```powershell
git fetch --all --prune
git status --short
git log --graph --decorate --oneline --date-order --max-count=120 --all
git diff --name-status origin/master...mistypatch
git diff --stat origin/master...mistypatch
git log --format="%H`t%an`t%ae`t%ad`t%s" --date=short --author="NyaMisty|Misty" --all
rg "Ghidra Mod|ghidramod|mistypatch|MetaCtrlFix|Esc2Exit|Modal" Ghidra .github PATCH.md
```

## 6. 重放后最小手工验收

- 打开 Listing，在函数变量操作数字段右键，确认没有错误的 `Edit Label`。
- 打开 xrefs，确认窗口行为：单选、Escape 关闭、跳转后关闭。
- 改一个 shared action 快捷键，保存后重启确认仍生效。
- 在 Meta/Ctrl 场景下测试同一 action 是否两个修饰键都能触发。
- 对已经是目标格式的整数 data/scalar 右键，确认不会出现重复 convert action。
- 打开 detached provider，按 Escape 只关闭该 provider，不触发主窗口 navigation。
