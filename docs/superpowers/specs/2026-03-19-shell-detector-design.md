# Shell 高危指令检测类库设计文档

**日期**: 2026-03-19
**版本**: 1.1

## 1. 项目概述

Linux Shell 高危指令检测 Java 类库，供其他系统集成使用。

## 2. 核心特性

- 白名单 + 黑名单模式，白名单优先
- 基于风险等级阈值拦截
- 使用 ANTLR 准确解析 Bash 语法，降低误报
- Fluent Builder API
- JSON 规则持久化
- 支持用户自定义规则的增删改

## 3. 需求确认

| 维度 | 选择 |
|------|------|
| 平台 | Linux 高危指令 + 用户自定义脚本 |
| 匹配方式 | 正则表达式 |
| 黑白名单配合 | 优先级模式（白名单优先） |
| 阈值 | 风险等级阈值 |
| API 风格 | Fluent Builder |
| 持久化 | 仅 JSON 格式 |

## 4. 包结构

```
com.example.shelldetector
├── ShellDetector.java              # 门面类 + Fluent Builder
├── core/
│   ├── DetectionEngine.java        # 检测逻辑编排
│   ├── RuleMatcher.java            # 正则匹配器
│   └── RiskEvaluator.java          # 风险评估
├── model/
│   ├── Rule.java                   # 规则实体
│   ├── RuleType.java               # WHITELIST / BLACKLIST
│   ├── DetectionResult.java        # 检测结果
│   └── RiskLevel.java              # 风险等级枚举
├── config/
│   └── DetectionConfig.java        # 全局配置
├── parser/
│   ├── BashLexer.g4                # ANTLR 词法
│   ├── BashParser.g4               # ANTLR 语法
│   ├── ShellAstListener.java       # AST 监听器
│   └── ShellCommandExtractor.java  # 命令提取器
├── persistence/
│   ├── RuleLoader.java             # 规则加载
│   └── RuleSaver.java              # 规则保存
├── exception/
│   ├── DetectionException.java
│   ├── InvalidPatternException.java
│   ├── RulePersistenceException.java
│   └── ShellParseException.java
└── builtin/
    └── BuiltinRules.java           # 内置规则
```

## 5. 核心数据模型

### 5.1 Rule 规则实体

```java
public class Rule {
    private String id;           // 规则唯一标识
    private String name;          // 规则名称
    private RuleType type;        // 白名单/黑名单
    private String pattern;       // 正则表达式
    private RiskLevel riskLevel;  // 风险等级
    private String description;   // 描述
    private boolean enabled;      // 是否启用

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private String id;
        private String name;
        private RuleType type = RuleType.BLACKLIST;
        private String pattern;
        private RiskLevel riskLevel = RiskLevel.RISK;
        private String description;
        private boolean enabled = true;

        public Builder id(String id);
        public Builder name(String name);
        public Builder type(RuleType type);
        public Builder whitelist();  // 设置为白名单
        public Builder blacklist();  // 设置为黑名单
        public Builder pattern(String pattern);
        public Builder riskLevel(RiskLevel riskLevel);
        public Builder description(String description);
        public Builder enabled(boolean enabled);
        public Rule build();
    }
}
```

### 5.2 RuleType 枚举

```java
public enum RuleType {
    WHITELIST,  // 白名单
    BLACKLIST    // 黑名单
}
```

### 5.3 RiskLevel 风险等级

```java
public enum RiskLevel {
    SAFE(0, "安全"),
    RISK(1, "风险"),
    DANGER(2, "高危");
}
```

### 5.4 DetectionResult 检测结果

```java
public class DetectionResult {
    private boolean passed;                    // 是否通过
    private List<Rule> matchedRules;           // 匹配到的规则
    private RiskLevel highestRiskLevel;        // 最高风险等级
    private String blockReason;               // 拦截原因
}
```

## 6. 检测流程

```
输入命令字符串
    ↓
【白名单检查 - 整条命令或全部子命令】
  ├─→ 整条命令匹配白名单？→ 是 → PASS
  └─→ 否 → 解析提取所有子命令
         ↓
         所有子命令都匹配白名单？→ 是 → PASS
         ↓ 否
【黑名单检测】
ANTLR Bash 语法解析 → AST
    ↓
从 AST 提取 SimpleCommand 列表
    ↓
对每个命令依次检测:
  ├─→ 黑名单匹配 → 匹配命中 → 记录风险等级
  └─→ 未命中 → 继续
    ↓
所有命令检测完成
    ↓
最高风险等级 vs 配置阈值
    ├─→ ≥ 阈值 → BLOCK（包含等于阈值）
    └─→ < 阈值 → PASS
```

**说明：**
- **白名单通过条件**（满足任一即可）：
  1. 整条输入命令字符串匹配白名单中的某条规则
  2. 解析拆解后的**所有**子命令都匹配白名单规则
- 白名单不是"有一个匹配就通过"，而是"全匹配才通过"或"整条匹配才通过"
- 阈值比较使用 `≥`（大于等于）：风险等级 ≥ 配置阈值则拦截

## 7. Shell 语法解析

使用 ANTLR 4 + 成熟的开源 Bash 语法文件，准确解析：
- 控制结构（if/then/else, while, for）
- 管道、重定向
- 变量赋值
- 子 shell

**ANTLR 语法文件来源：** 使用已有的成熟开源 Bash 语法实现（如 antlr/grammars-v4 仓库中的 bash 语法），无需自行编写。

只提取 SimpleCommand 进行检测

## 8. 内置规则

| 分类 | 风险等级 | 示例指令/模式 |
|------|----------|--------------|
| 灾难性破坏 | DANGER | `rm -rf /`, `mkfs.*`, `dd of=/dev/sda`, `:(){ :|:& };:` |
| 系统控制 | DANGER | `reboot`, `shutdown`, `init 0/6`, `systemctl poweroff/reboot`, `halt`, `poweroff` |
| 文件删除 | RISK | `rm -rf`, `rm -r`, `rmdir --ignore-fail-on-non-empty`, `unlink` |
| 文件覆盖 | RISK | `> file`, `1> file`, `2> file`, `&> file`, `cp -f`, `mv` |
| 文件创建/修改 | RISK | `touch`, `mkdir -p`, `cat >`, `echo >`, `tee`, `sed -i`, `awk -i`, `perl -i`, `chattr`, `setfacl`, `install`, `ln -s`, `ln` |
| 权限修改 | RISK | `chmod 777`, `chmod -R`, `chown -R`, `chgrp -R` |
| 进程控制 | RISK | `kill -9`, `pkill -9`, `killall -9` |
| 查看类命令 | SAFE | `cat`, `ls`, `echo`, `printf`, `pwd`, `whoami`, `id`, `date`, `uptime`, `ps`, `top`, `head`, `tail`, `less`, `more`, `grep`, `find`, `wc`, `stat`, `file` |

**文件创建/修改类指令补充说明：**
- `touch` - 创建文件或修改时间戳
- `mkdir -p` - 递归创建目录
- `cat > file` - 通过 cat 重定向创建/覆盖文件
- `echo > file` - 通过 echo 重定向创建/覆盖文件
- `tee` - 读取标准输入并写入文件
- `sed -i` - 原地修改文件
- `awk -i inplace` - 原地修改文件
- `perl -i` - 原地修改文件
- `chattr` - 修改文件属性
- `setfacl` - 设置文件 ACL
- `install` - 复制文件并设置属性
- `ln -s / ln` - 创建符号链接或硬链接

## 9. API 设计

### 9.1 Fluent Builder 示例

```java
// 快速使用
ShellDetector detector = ShellDetector.createDefault();
DetectionResult result = detector.detect("rm -rf /");

// 自定义配置
ShellDetector detector = ShellDetector.builder()
    .withDefaultRules()
    .withRulesFromJson("rules.json")
    .withThreshold(RiskLevel.RISK)
    .build();

// 动态管理规则
detector.addRule(Rule.builder()
    .id("my-script")
    .name("my-dangerous-script")
    .blacklist()
    .pattern("./danger-script\\.sh.*")
    .riskLevel(RiskLevel.DANGER)
    .description("我的危险脚本")
    .enabled(true)
    .build());

detector.removeRule("my-script");
detector.updateRule(modifiedRule);

// 持久化
detector.saveRulesToJson("rules.json");
```

### 9.2 规则 JSON 格式

```json
{
  "version": "1.0",
  "rules": [
    {
      "id": "builtin-rm-rf-root",
      "name": "rm -rf root",
      "type": "BLACKLIST",
      "pattern": "rm\\s+-.*-rf.*\\s+/.*",
      "riskLevel": "DANGER",
      "description": "递归删除根目录",
      "enabled": true
    }
  ]
}
```

## 10. 异常处理

- `DetectionException` - 检测异常基类
- `InvalidPatternException` - 无效的正则表达式
- `RulePersistenceException` - 规则持久化失败
- `ShellParseException` - Shell 语法解析失败
