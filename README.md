# Shell 高危指令检测类库

Linux Shell 高危指令检测 Java 类库，供其他系统集成使用。

## 功能特性

- 白名单 + 黑名单模式，白名单优先
- 基于风险等级阈值拦截
- 支持用户自定义规则的增删改
- Fluent Builder API
- JSON 规则持久化

## 快速开始

```java
// 使用默认配置和内置规则
ShellDetector detector = ShellDetector.createDefault();
DetectionResult result = detector.detect("rm -rf /");

if (!result.isPassed()) {
    System.out.println("Blocked: " + result.getBlockReason());
}
```

## 自定义配置

```java
ShellDetector detector = ShellDetector.builder()
    .withDefaultRules()
    .withThreshold(RiskLevel.DANGER)  // 只拦截高危
    .withRulesFromJson("my-rules.json")
    .build();
```

## 动态管理规则

```java
detector.addRule(Rule.builder()
    .id("my-script")
    .name("My Dangerous Script")
    .blacklist()
    .pattern("./danger\\.sh.*")
    .riskLevel(RiskLevel.DANGER)
    .description("My custom dangerous script")
    .build());

detector.saveRulesToJson("rules.json");
```

## 风险等级

- `SAFE` - 安全
- `RISK` - 风险
- `DANGER` - 高危

## 构建项目

```bash
mvn clean install
```
