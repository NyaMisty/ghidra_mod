# Current UI and workflow mods

本文件只记录当前 `mistypatch` 已提交并保留的 UI/交互类补丁。历史上出现过但当前不在保留补丁序列里的修改放在 [historical-and-dropped-mods.md](historical-and-dropped-mods.md)。

## 1. Listing 中变量操作数不启用 Edit Label

状态：`current-retained`

原始意图：
在 Listing 视图里，函数操作数已有 `EditNameAction` 处理，函数变量操作数已有 `EditOperandNameAction` 处理。原版 `EditLabelAction` 在这些位置仍可能出现在右键菜单里，容易出现重复或错误的编辑入口。该补丁让变量操作数字段不再启用 `EditLabelAction`。

实现方式：

- 修改 `Ghidra/Features/Base/src/main/java/ghidra/app/plugin/core/label/EditLabelAction.java`。
- 在 `isEnabledForContext` 中先取 `ProgramLocation`，当位置是 `OperandFieldLocation` 时统一处理。
- 若 symbol 是 `SymbolType.FUNCTION`，保留原逻辑：函数操作数字段交给 `EditNameAction`。
- 若 `OperandFieldLocation.getVariableOffset() != null`，说明是函数变量操作数字段，直接返回 `false`，交给 `EditOperandNameAction`。

历史迁移：

- 最早手工提交：`d2639e365e025d8f7bbca7a8884e1145e1b1e3a1`，作者 `NyaMisty <misty@misty.moe>`。
- 当前 `mistypatch` 版本：`340ba07f4ff1c865a8207965dfa60b514af0043a`。
- `stable` 对应版本：`8e7313efb5c2415e6ec2f2431c0e129227cafaa8`。
- 还存在 `670f3332cb3c809f71293fb24a78b055791a317b`、`0e13f0435f0a29e73459c4b18b7886ec6c6a86d3` 等不同分支/重放版本，内容等价。

未来合并提示：

- 重点看 upstream 是否重写了 `EditLabelAction.isEnabledForContext` 或 `OperandFieldLocation` 的变量判断 API。
- 该补丁行为很窄，若发生冲突，优先保留“变量操作数不显示 Edit Label”的用户可见行为，而不是保留原始代码形状。

## 2. Location References 窗口模态化

状态：`current-retained`

原始意图：
把“查找引用/Location References”结果窗口从普通 dockable provider 调整成更接近模态选择器的体验：单选引用、Enter/双击跳转后关闭、Escape 关闭，避免选择一行时自动导航导致主窗口位置被频繁改写。

实现方式：

- 修改 `LocationReferencesPanel`：
  - 给 panel 设置 client property `ghidramod.modalcomponent`。
  - 表格改为单选。
  - 关闭 `navigateOnSelection`。
  - 包装 `GoToService`，在 `goTo` 成功或调用后关闭 provider 并调用 `closeComponent()`，避免下次打开为空。
  - 安装 Escape key listener 来关闭窗口。
- 新增 `Ghidra/Features/Base/src/main/java/ghidra/app/services/GoToServiceWrap.java`：
  - 代理 `GoToService` 的所有方法，便于覆写部分导航行为。
- 修改 `LocationReferencesProvider`：
  - 禁用 `SelectionNavigationAction` 的本地 action 注册。
- 修改 Docking 框架：
  - `DetachedWindowNode` 识别 `ghidramod.modalcomponent`，强制用 modal `JDialog`。
  - `window.setVisible(true)` 改为 `SwingUtilities.invokeLater(...)`，避免 modal dialog 在创建路径上阻塞。
  - `close()` 对 modal dialog 额外 `setVisible(false)`。
  - `Ghidra/Framework/Docking/src/main/java/docking/DockingWindowManager.java` 中的 `movePlaceholderToFront` 对 `JDialog` 延后 `toFront`。

历史迁移：

- 旧分支提交：`8677a50d4d187c0ad89aa8d789592aafe9b6e081`。
- 当前 `mistypatch` 版本：`51a30a33823f5585c75b88d2837ec7de207d1bc4`。
- `stable` 对应版本：`25ee4da9ac4bd9a7a734852e7bd1b69f36887589`。
- 2025-10-06 `Fix to latest version` 中修正了 `LocationReferencesPanel` 的初始化顺序，改为从 tool 获取 `GoToService` 后再包装。

未来合并提示：

- 这是最容易和 Docking upstream 冲突的 UI 补丁之一，因为它同时改了 Base feature 和 Framework/Docking。
- 若 upstream 改动 LocationReferences 的导航模型，需要重新确认三件事：单选、选择不自动跳转、跳转后关闭。
- `ghidramod.modalcomponent` 是跨模块约定，没有类型安全保护，迁移时要同时搜索 panel 和 `DetachedWindowNode`。

## 3. Shared action 快捷键可修改

状态：`current-retained`

原始意图：
Ghidra 的部分 shared action 原本会被 key binding UI 忽略，导致用户不能在设置中修改这些动作的快捷键。该补丁放宽过滤规则，让更多 shared action 进入可配置列表。

实现方式：

- 修改 `Ghidra/Framework/Docking/src/main/java/docking/actions/KeyBindingUtils.java`。
- 新增 `isIgnored2(DockingActionIf action)`：
  - 不支持 key binding 的 action 仍忽略。
  - `KeyBindingPrecedence.SystemActionsLevel` 的 action 仍忽略。
  - 其他 action 允许进入 key binding action map。
- `getKeyBindingActionsForOwner` 中改用 `isIgnored2`。

历史迁移：

- 旧分支提交：`6bcd7b8e2014d91cf8003b38054730ba79281c42`。
- 当前 `mistypatch` 版本：`76368d9078892c699f1541931291900ce32364a5`。
- `stable` 对应版本：`662d6279c5e34676f7cbe2d1d192d671cf68e1a2`。
- 2025-10-06 迁移时将过滤级别从旧写法调整为 `SystemActionsLevel`。

未来合并提示：

- 每次追上游都要看 `KeyBindingPrecedence` 枚举和 `KeyBindingUtils.isIgnored(...)` 的语义是否变了。
- 这个补丁的风险是暴露本来被系统保留的动作，合并后最好打开 Key Bindings 设置页检查 shared action 是否仍可见且没有污染 system action。

## 4. Meta 和 Ctrl 快捷键互相映射

状态：`current-retained`

原始意图：
让使用 Meta 或 Ctrl 的快捷键在不同平台/键盘习惯下都能触发，减少 macOS/Windows/Linux 或远程桌面场景中快捷键不可用的问题。

实现方式：

- 修改 `KeyBindingUtils`：
  - 新增 `META_CTRL_MASK`、`UNIFY_CTRL`、`isMetaCtrlKeyStroke(...)`、`convertMetaCtrlKeyStroke(...)`。
  - 发现 keystroke 含 Meta/Ctrl 修饰符时，先规范化为统一修饰符。
- 修改 `KeyBindings`：
  - 保存新的 key stroke 前做规范化。
- 修改 `KeyBindingsManager`：
  - `doAddKeyBinding` 包装为两层。
  - 对包含 Meta/Ctrl 的 binding 同时注册 Meta 和 Ctrl 两个映射。
  - 若 action 原本的 key binding 需要规范化，使用 `TestUtils.setInstanceField("keyBindingData", ...)` 直接更新真实 `DockingAction` 的字段。

历史迁移：

- 旧分支提交：`ae1df1bb7c524b7f84d162763c78bb2203846637`。
- 当前 `mistypatch` 版本：`6a5283b67ce92ade90b2802ca3dc21de5fcd8c77`。
- `stable` 对应版本：`81edd9734cb486a12677169c11ce42a13301b75a`。
- 2025-10-06 迁移中补了 `InputEvent` import，并移除了已不需要的 `ReservedKeyBindings` import。

未来合并提示：

- 生产代码依赖 `generic.test.TestUtils` 是明显的维护风险。若 upstream 改了 action/keyBindingData 的字段名或模块依赖，这里最容易坏。
- 合并后需要手工验证：设置一个 Ctrl 快捷键后 Meta 是否触发；设置一个 Meta 快捷键后 Ctrl 是否触发；保存/重启后配置是否仍然规范化。

## 5. ConvertAction 在格式相同时不启用

状态：`current-retained`

原始意图：
当当前 data/scalar 已经是目标格式和 signedness 时，不再显示或启用“Convert to ...”动作，减少右键菜单噪音和重复快捷键入口。

实现方式：

- 修改 `Ghidra/Features/Base/src/main/java/ghidra/app/plugin/core/equate/AbstractConvertAction.java`。
- 对 `AbstractIntegerDataType`：
  - 用 `FormatSettingsDefinition.DEF.getChoice(data)` 获取当前显示格式。
  - 若当前格式等于 `getFormatChoice()` 且 signedness 等于 action 目标 `isSigned`，返回 `false`。

历史迁移：

- 旧分支提交：`9640eb21e1ae2ab4bb258f70ab993198f1288358`。
- 当前 `mistypatch` 版本：`aa9499fc53a8b02e0bfa54d120a18f6275ec0a21`。
- `stable` 对应版本：`1ac81a35ac44a4b7bbed2c1e21f31d211a7389a6`。

未来合并提示：

- 检查 upstream 是否调整了 `FormatSettingsDefinition` 或 integer data type signedness 逻辑。
- 该补丁只影响 action enablement，不应改变实际转换命令。

## 6. Detached Window 支持 Escape 关闭

状态：`current-retained`

原始意图：
浮动/分离窗口常用作临时查看窗口，用 Escape 快速关闭更高效，也和模态 xref 窗口补丁配合。

实现方式：

- 修改 `Ghidra/Framework/Docking/src/main/java/docking/DetachedWindowNode.java`。
- 新增 `installEscapeAction()`：
  - 从 `JDialog` 或 `JFrame` 取 root pane。
  - 用 `KeyBindingUtils.registerAction(...)` 在 `WHEN_ANCESTOR_OF_FOCUSED_COMPONENT` 范围绑定 Escape。
  - action 调用 `close()`。
- 在 `createWindow(...)` 创建 window 后安装该 action。

历史迁移：

- 旧分支提交：`0b31f3ad5cd959a4740d868f0392ae7e3b0e0cb4`。
- 当前 `mistypatch` 版本：`cd7e1ddbd827544da1fce75b404c919a5be56eaa`。
- `stable` 对应版本：`70e2feb833f1fb349010aed1b0a7a2bbb4705a62`。
- 2025-10-06 迁移中给 `NextPrevAddressPlugin` 加了 active frame 检查，避免 Escape 同时触发 popup view 和主 view 的导航动作。

未来合并提示：

- 合并后检查所有 detached provider：Escape 是否关闭当前 detached window，而不是触发主 tool 的上/下导航。
- 如果 upstream 修改 window lifecycle，需要确认 `close()` 仍是正确入口。

## 7. Next/Previous Address 在主窗口非 active 时不启用

状态：`current-retained`

原始意图：
配合 Escape 关闭 detached window，避免焦点在 detached/modal 窗口时，主窗口的 navigation action 也响应快捷键。

实现方式：

- 修改 `Ghidra/Features/Base/src/main/java/ghidra/app/plugin/core/navigation/NextPrevAddressPlugin.java`。
- 在 action `isEnabledForContext(...)` 开头检查 `tool.getToolFrame()`。
- 若 tool frame 存在但不是 active，返回 `false`。

历史迁移：

- 作为 2025-10-06 `Fix to latest version` 的一部分进入当前补丁序列。
- 当前 `mistypatch` 提交：`7081580c919622fc40ec105edd2f54b82693d026`。
- `stable` 对应提交：`1634aef4f4b90b3cc454ec33cfee907ba175c5d5`。

未来合并提示：

- 这是 Escape close 的保护补丁，不能只迁移 `DetachedWindowNode` 而漏掉这里。
- 如果 upstream 改了 navigation action enablement，应重新验证 detached/modal 窗口焦点场景。

## 8. Functions View 支持删除函数

状态：`current-retained`

原始意图：
让 Functions View 中选中的函数可以直接通过 Delete 键或右键菜单删除，不必切回 Listing 视图再触发现有 `DeleteFunctionAction`。

实现方式：

- 修改 `Ghidra/Features/Base/src/main/java/ghidra/app/plugin/core/function/DeleteFunctionAction.java`。
- 新增 package-private `DeleteFunctionActionNoListing extends DockingAction`：
  - action 名称为 `Delete Function (FunctionsView)`。
  - context class 设为 `FunctionSupplierContext`。
  - popup menu 为 `Delete Function(s)`。
  - key binding 为 `Delete`。
  - `isEnabledForContext(...)` 排除 `ListingActionContext`，并要求 `context.hasFunctions()`。
  - `actionPerformed(...)` 遍历 `context.getFunctions()`，对每个 function entry 执行 `DeleteFunctionCmd`。
- 修改 `Ghidra/Features/Base/src/main/java/ghidra/app/plugin/core/function/FunctionPlugin.java`：
  - 在 function actions 初始化时注册 `new DeleteFunctionActionNoListing(this)`。

历史迁移：

- 当前提交：`534c6bd3f85c001f790f052cd60dea205eba5e89`，作者 `Misty <gyc990326@gmail.com>`，提交信息 `[mistypatch] feat: Allow deleting functions from Functions view`。
- 当前 `mistypatch` 指向该提交。

未来合并提示：

- 追上游时重点检查 `FunctionSupplierContext`、`FunctionPlugin` action 注册顺序和 `DeleteFunctionAction` 是否被 upstream 重构。
- 当前实现遇到 null function 会 `return`，会停止处理后续选中项；如果 upstream 或用户期望批量删除跳过 null，未来可改成 `continue`。
- 因为该 action 复用 Delete 键，合并后要确认 Listing 删除动作和 Functions View 删除动作不会在同一 context 下同时启用。
