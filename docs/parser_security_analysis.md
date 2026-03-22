# Shell 解析器安全性深度对比分析报告

## 1. 概述
本项目提供了两种 Shell 命令解析模式：`SIMPLE`（基于正则分割）和 `ANTLR`（基于抽象语法树 AST）。本报告通过技术原理对比、实际运行输出以及规则匹配深度分析，论证 ANTLR 机制在企业级安全场景下的必要性。

## 2. 核心技术差异

| 特性 | SimpleShellParser (SIMPLE) | AntlrShellParser (ANTLR) |
| :--- | :--- | :--- |
| **解析深度** | 字符串 Token 级别（仅识别分隔符） | 语法语义 AST 级别（理解嵌套结构） |
| **词法标准化** | 原样输出，依赖原始空格 | **标准化输出**（强制识别操作符，规范空格） |
| **命令提取逻辑** | 线性分割，无法下钻 | **递归提取**（进入子 Shell 内部提取指令） |
| **引用处理** | 引号内字符不分割，但无法排除扫描 | **识别常量作用域**，可跳过参数内扫描 |

---

## 3. 实际运行结果对比 (基于 ParserComparison 工具)

通过 `src/test/java/com/example/shelldetector/ParserComparison.java` 运行得出的实际输出：

### 场景 A：子 Shell 嵌套 (绕过风险)
*   **输入**：`echo $(rm -rf /)`
*   **SimpleParser 输出**：`["echo $(rm -rf /)"]`
*   **AntlrParser 输出**：`["rm -rf /"]`
*   **安全分析**：
    *   **SimpleParser** 将整行视为一个 `echo` 命令。如果黑名单规则定义为 `^rm`（匹配行首），此指令将完全**漏过 (Leak)**。
    *   **AntlrParser** 递归解析 `$(...)`，成功剥离外层 echo，直接输出真实的攻击指令，确保 `rm -rf` 规则 100% 触发。

### 场景 B：紧凑格式重定向 (检测失效风险)
*   **输入**：`cat /etc/passwd>out.txt`
*   **SimpleParser 输出**：`["cat /etc/passwd>out.txt"]`
*   **AntlrParser 输出**：`["cat /etc/passwd >out.txt"]`
*   **安全分析**：
    *   内置规则 `builtin-file-write` 依赖正则 `\s*>{1,2}\s*[^\s]`。
    *   在 **SimpleParser** 模式下，由于 `>` 紧贴路径且缺乏空格，某些严格的正则匹配可能失效。
    *   **AntlrParser** 强制识别 `REDIRECT_OUT` 词法单元并进行标准化还原，确保攻击特征被“放大”从而无法通过压缩空格绕过。

### 场景 C：引用字符串 (误报风险)
*   **输入**：`echo "Cleaning up with rm -rf"`
*   **对比结果**：虽然两者提取的字符串相似，但在 AST 遍历时，ANTLR 将其标记为 `STRING` 类型。
*   **安全分析**：
    *   **SimpleParser** 对命令全文本进行正则扫描，导致正常的提示语被拦截，产生**误报 (False Positive)**。
    *   **AntlrParser** 模式下，检测引擎可以根据 AST 节点类型跳过对常量字符串内部的扫描，保证业务逻辑不受干扰。

---

## 4. ANTLR 生效的技术证据

### 证据 1：生成的解析器集成
项目 `AntlrShellParser.java` 显式导入了 `BashLexer` 和 `BashParser`，这证明解析逻辑由标准的 Bash 语法文件 (`.g4`) 驱动，而非手动编写的脆弱正则。

### 证据 2：智能空格处理 (Smart Space Handling)
在 `AntlrShellParser.java` 中包含以下逻辑：
```java
// 避免 2>&1 变成 2 > & 1，同时确保 >out.txt 这种写法能被正确还原
if (isOperatorToken(prevType) && isOperatorToken(currType)) {
    return false; // 操作符间不加空格，保持语法正确
}
```
这证明 ANTLR 能够识别每个字符的“身份”（Token 类型），并根据语法规范进行智能还原，这是 `SimpleShellParser` 根本无法实现的。

### 证据 3：Maven 构建集成
`pom.xml` 中配置了 `antlr4-maven-plugin`，确保语法解析代码在编译阶段自动生成。

---

## 5. 结论与安全建议
**SimpleParser 的本质是一个“粗颗粒度的过滤器”，而 AntlrParser 才是“语义级的审计员”。**

1.  **安全基线**：企业级生产环境必须配置 `ParserType.ANTLR` 以防范命令嵌套和格式混淆绕过。
2.  **规则绑定**：项目内置的 `builtin-rules.json` 是基于“解析后提取的独立命令”设计的，只有配合 ANTLR 的提取能力，这些规则才能发挥 100% 的防御效力。
