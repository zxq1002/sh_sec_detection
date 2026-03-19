# Shell 高危指令检测类库实现计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 构建一个 Linux Shell 高危指令检测 Java 类库，支持黑白名单、风险等级阈值、ANTLR 语法解析、Fluent API、JSON 持久化。

**Architecture:** 采用分层设计：Model 层定义数据结构，Core 层实现检测逻辑，Parser 层处理 ANTLR 语法解析，Persistence 层处理 JSON 持久化，API 层提供 Fluent Builder 门面。

**Tech Stack:** Java 8+, ANTLR 4, Jackson (JSON), JUnit 5, Maven

---

## 文件结构

```
sh_sec_detection/
├── pom.xml
├── src/
│   ├── main/
│   │   ├── java/com/example/shelldetector/
│   │   │   ├── ShellDetector.java
│   │   │   ├── core/
│   │   │   │   ├── DetectionEngine.java
│   │   │   │   ├── RuleMatcher.java
│   │   │   │   └── RiskEvaluator.java
│   │   │   ├── model/
│   │   │   │   ├── Rule.java
│   │   │   │   ├── RuleType.java
│   │   │   │   ├── DetectionResult.java
│   │   │   │   └── RiskLevel.java
│   │   │   ├── config/
│   │   │   │   └── DetectionConfig.java
│   │   │   ├── parser/
│   │   │   │   ├── ShellAstListener.java
│   │   │   │   └── ShellCommandExtractor.java
│   │   │   ├── persistence/
│   │   │   │   ├── RuleLoader.java
│   │   │   │   └── RuleSaver.java
│   │   │   ├── exception/
│   │   │   │   ├── DetectionException.java
│   │   │   │   ├── InvalidPatternException.java
│   │   │   │   ├── RulePersistenceException.java
│   │   │   │   └── ShellParseException.java
│   │   │   └── builtin/
│   │   │       └── BuiltinRules.java
│   │   └── resources/
│   │       ├── antlr/
│   │       │   ├── BashLexer.g4
│   │       │   └── BashParser.g4
│   │       └── builtin-rules.json
│   └── test/
│       └── java/com/example/shelldetector/
│           ├── model/
│           ├── core/
│           ├── parser/
│           ├── persistence/
│           └── ShellDetectorTest.java
└── docs/superpowers/
    └── specs/2026-03-19-shell-detector-design.md
```

---

## 实现任务

### Task 1: 项目初始化和构建配置

**Files:**
- Create: `pom.xml`

- [ ] **Step 1: 创建 Maven pom.xml**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <groupId>com.example</groupId>
    <artifactId>shell-detector</artifactId>
    <version>1.0.0-SNAPSHOT</version>
    <packaging>jar</packaging>

    <name>Shell Detector</name>
    <description>Linux Shell 高危指令检测类库</description>

    <properties>
        <maven.compiler.source>1.8</maven.compiler.source>
        <maven.compiler.target>1.8</maven.compiler.target>
        <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
        <antlr.version>4.13.1</antlr.version>
        <jackson.version>2.15.2</jackson.version>
        <junit.version>5.10.0</junit.version>
    </properties>

    <dependencies>
        <!-- ANTLR -->
        <dependency>
            <groupId>org.antlr</groupId>
            <artifactId>antlr4-runtime</artifactId>
            <version>${antlr.version}</version>
        </dependency>

        <!-- Jackson JSON -->
        <dependency>
            <groupId>com.fasterxml.jackson.core</groupId>
            <artifactId>jackson-databind</artifactId>
            <version>${jackson.version}</version>
        </dependency>

        <!-- JUnit 5 (测试) -->
        <dependency>
            <groupId>org.junit.jupiter</groupId>
            <artifactId>junit-jupiter-api</artifactId>
            <version>${junit.version}</version>
            <scope>test</scope>
        </dependency>
        <dependency>
            <groupId>org.junit.jupiter</groupId>
            <artifactId>junit-jupiter-engine</artifactId>
            <version>${junit.version}</version>
            <scope>test</scope>
        </dependency>
    </dependencies>

    <build>
        <plugins>
            <plugin>
                <groupId>org.antlr</groupId>
                <artifactId>antlr4-maven-plugin</artifactId>
                <version>${antlr.version}</version>
                <executions>
                    <execution>
                        <goals>
                            <goal>generate</goal>
                        </goals>
                        <configuration>
                            <sourceDirectory>src/main/resources/antlr</sourceDirectory>
                            <outputDirectory>${project.build.directory}/generated-sources/antlr4</outputDirectory>
                        </configuration>
                    </execution>
                </executions>
            </plugin>
            <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-compiler-plugin</artifactId>
                <version>3.11.0</version>
                <configuration>
                    <source>${maven.compiler.source}</source>
                    <target>${maven.compiler.target}</target>
                </configuration>
            </plugin>
            <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-surefire-plugin</artifactId>
                <version>3.1.2</version>
            </plugin>
        </plugins>
    </build>
</project>
```

- [ ] **Step 2: 创建目录结构**

```bash
mkdir -p src/main/java/com/example/shelldetector/{core,model,config,parser,persistence,exception,builtin}
mkdir -p src/main/resources/antlr
mkdir -p src/test/java/com/example/shelldetector/{core,model,parser,persistence}
```

- [ ] **Step 3: 验证项目结构**

运行: `ls -la`
验证: 目录结构正确

---

### Task 2: 异常类定义

**Files:**
- Create: `src/main/java/com/example/shelldetector/exception/DetectionException.java`
- Create: `src/main/java/com/example/shelldetector/exception/InvalidPatternException.java`
- Create: `src/main/java/com/example/shelldetector/exception/RulePersistenceException.java`
- Create: `src/main/java/com/example/shelldetector/exception/ShellParseException.java`

- [ ] **Step 1: 创建 DetectionException 基类**

```java
package com.example.shelldetector.exception;

public class DetectionException extends RuntimeException {
    public DetectionException(String message) {
        super(message);
    }

    public DetectionException(String message, Throwable cause) {
        super(message, cause);
    }
}
```

- [ ] **Step 2: 创建 InvalidPatternException**

```java
package com.example.shelldetector.exception;

public class InvalidPatternException extends DetectionException {
    public InvalidPatternException(String message) {
        super(message);
    }

    public InvalidPatternException(String message, Throwable cause) {
        super(message, cause);
    }
}
```

- [ ] **Step 3: 创建 RulePersistenceException**

```java
package com.example.shelldetector.exception;

public class RulePersistenceException extends DetectionException {
    public RulePersistenceException(String message) {
        super(message);
    }

    public RulePersistenceException(String message, Throwable cause) {
        super(message, cause);
    }
}
```

- [ ] **Step 4: 创建 ShellParseException**

```java
package com.example.shelldetector.exception;

public class ShellParseException extends DetectionException {
    public ShellParseException(String message) {
        super(message);
    }

    public ShellParseException(String message, Throwable cause) {
        super(message, cause);
    }
}
```

- [ ] **Step 5: 编译验证**

运行: `mvn compile -pl . -am`
预期: BUILD SUCCESS

---

### Task 3: Model 层 - 枚举类

**Files:**
- Create: `src/main/java/com/example/shelldetector/model/RuleType.java`
- Create: `src/main/java/com/example/shelldetector/model/RiskLevel.java`

- [ ] **Step 1: 创建 RuleType 枚举**

```java
package com.example.shelldetector.model;

public enum RuleType {
    WHITELIST,
    BLACKLIST
}
```

- [ ] **Step 2: 创建 RiskLevel 枚举**

```java
package com.example.shelldetector.model;

public enum RiskLevel {
    SAFE(0, "安全"),
    RISK(1, "风险"),
    DANGER(2, "高危");

    private final int level;
    private final String description;

    RiskLevel(int level, String description) {
        this.level = level;
        this.description = description;
    }

    public int getLevel() {
        return level;
    }

    public String getDescription() {
        return description;
    }

    public boolean isHigherOrEqualTo(RiskLevel other) {
        return this.level >= other.level;
    }
}
```

- [ ] **Step 3: 编译验证**

运行: `mvn compile`
预期: BUILD SUCCESS

---

### Task 4: Config 配置类

**Files:**
- Create: `src/main/java/com/example/shelldetector/config/DetectionConfig.java`

- [ ] **Step 1: 创建 DetectionConfig 类**

```java
package com.example.shelldetector.config;

import com.example.shelldetector.model.RiskLevel;

import java.io.Serializable;

public class DetectionConfig implements Serializable {
    private RiskLevel threshold = RiskLevel.RISK;
    private boolean failOnParseError = true;

    public DetectionConfig() {
    }

    public RiskLevel getThreshold() {
        return threshold;
    }

    public void setThreshold(RiskLevel threshold) {
        this.threshold = threshold;
    }

    public boolean isFailOnParseError() {
        return failOnParseError;
    }

    public void setFailOnParseError(boolean failOnParseError) {
        this.failOnParseError = failOnParseError;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private DetectionConfig config = new DetectionConfig();

        public Builder threshold(RiskLevel threshold) {
            config.threshold = threshold;
            return this;
        }

        public Builder failOnParseError(boolean failOnParseError) {
            config.failOnParseError = failOnParseError;
            return this;
        }

        public DetectionConfig build() {
            return config;
        }
    }
}
```

- [ ] **Step 2: 编译验证**

运行: `mvn compile`
预期: BUILD SUCCESS

---

### Task 5: Model 层 - Rule 和 DetectionResult

**Files:**
- Create: `src/main/java/com/example/shelldetector/model/Rule.java`
- Create: `src/main/java/com/example/shelldetector/model/DetectionResult.java`
- Test: `src/test/java/com/example/shelldetector/model/RuleTest.java`
- Test: `src/test/java/com/example/shelldetector/model/RiskLevelTest.java`

- [ ] **Step 1: 创建 Rule 类 (含 Builder 和 Jackson 注解)**

```java
package com.example.shelldetector.model;

import com.example.shelldetector.exception.InvalidPatternException;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.io.Serializable;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

public class Rule implements Serializable {
    @JsonProperty("id")
    private String id;

    @JsonProperty("name")
    private String name;

    @JsonProperty("type")
    private RuleType type;

    @JsonProperty("pattern")
    private String pattern;

    @JsonIgnore
    private transient Pattern compiledPattern;

    @JsonProperty("riskLevel")
    private RiskLevel riskLevel;

    @JsonProperty("description")
    private String description;

    @JsonProperty("enabled")
    private boolean enabled;

    private Rule() {
    }

    public String getId() { return id; }
    public String getName() { return name; }
    public RuleType getType() { return type; }
    public String getPattern() { return pattern; }
    public RiskLevel getRiskLevel() { return riskLevel; }
    public String getDescription() { return description; }
    public boolean isEnabled() { return enabled; }

    @JsonIgnore
    public Pattern getCompiledPattern() {
        if (compiledPattern == null && pattern != null) {
            try {
                compiledPattern = Pattern.compile(pattern);
            } catch (PatternSyntaxException e) {
                throw new InvalidPatternException("Invalid regex pattern: " + pattern, e);
            }
        }
        return compiledPattern;
    }

    public boolean matches(String command) {
        if (!enabled || pattern == null) {
            return false;
        }
        return getCompiledPattern().matcher(command).find();
    }

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

        public Builder id(String id) {
            this.id = id;
            return this;
        }

        public Builder name(String name) {
            this.name = name;
            return this;
        }

        public Builder type(RuleType type) {
            this.type = type;
            return this;
        }

        public Builder whitelist() {
            this.type = RuleType.WHITELIST;
            return this;
        }

        public Builder blacklist() {
            this.type = RuleType.BLACKLIST;
            return this;
        }

        public Builder pattern(String pattern) {
            this.pattern = pattern;
            return this;
        }

        public Builder riskLevel(RiskLevel riskLevel) {
            this.riskLevel = riskLevel;
            return this;
        }

        public Builder description(String description) {
            this.description = description;
            return this;
        }

        public Builder enabled(boolean enabled) {
            this.enabled = enabled;
            return this;
        }

        public Rule build() {
            Rule rule = new Rule();
            rule.id = this.id;
            rule.name = this.name;
            rule.type = this.type;
            rule.pattern = this.pattern;
            rule.riskLevel = this.riskLevel;
            rule.description = this.description;
            rule.enabled = this.enabled;
            return rule;
        }
    }
}
```

- [ ] **Step 2: 创建 DetectionResult 类**

```java
package com.example.shelldetector.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class DetectionResult implements Serializable {
    @JsonProperty("passed")
    private final boolean passed;

    @JsonProperty("matchedRules")
    private final List<Rule> matchedRules;

    @JsonProperty("highestRiskLevel")
    private final RiskLevel highestRiskLevel;

    @JsonProperty("blockReason")
    private final String blockReason;

    private DetectionResult(Builder builder) {
        this.passed = builder.passed;
        this.matchedRules = Collections.unmodifiableList(new ArrayList<>(builder.matchedRules));
        this.highestRiskLevel = builder.highestRiskLevel;
        this.blockReason = builder.blockReason;
    }

    public boolean isPassed() { return passed; }
    public List<Rule> getMatchedRules() { return matchedRules; }
    public RiskLevel getHighestRiskLevel() { return highestRiskLevel; }
    public String getBlockReason() { return blockReason; }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private boolean passed = true;
        private List<Rule> matchedRules = new ArrayList<>();
        private RiskLevel highestRiskLevel = RiskLevel.SAFE;
        private String blockReason;

        public Builder passed(boolean passed) {
            this.passed = passed;
            return this;
        }

        public Builder addMatchedRule(Rule rule) {
            this.matchedRules.add(rule);
            if (rule.getRiskLevel().isHigherOrEqualTo(this.highestRiskLevel)) {
                this.highestRiskLevel = rule.getRiskLevel();
            }
            return this;
        }

        public Builder highestRiskLevel(RiskLevel level) {
            this.highestRiskLevel = level;
            return this;
        }

        public Builder blockReason(String reason) {
            this.blockReason = reason;
            return this;
        }

        public DetectionResult build() {
            return new DetectionResult(this);
        }
    }
}
```

- [ ] **Step 3: 编写测试**

```java
package com.example.shelldetector.model;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class RuleTest {

    @Test
    void testRuleBuilder() {
        Rule rule = Rule.builder()
                .id("test-id")
                .name("test-rule")
                .blacklist()
                .pattern("rm\\s+-rf")
                .riskLevel(RiskLevel.DANGER)
                .description("测试规则")
                .enabled(true)
                .build();

        assertEquals("test-id", rule.getId());
        assertEquals("test-rule", rule.getName());
        assertEquals(RuleType.BLACKLIST, rule.getType());
        assertEquals("rm\\s+-rf", rule.getPattern());
        assertEquals(RiskLevel.DANGER, rule.getRiskLevel());
        assertTrue(rule.isEnabled());
    }

    @Test
    void testPatternMatching() {
        Rule rule = Rule.builder()
                .pattern("rm\\s+-rf")
                .build();

        assertTrue(rule.matches("rm -rf /tmp"));
        assertFalse(rule.matches("ls -la"));
    }

    @Test
    void testDisabledRuleDoesNotMatch() {
        Rule rule = Rule.builder()
                .pattern("rm\\s+-rf")
                .enabled(false)
                .build();

        assertFalse(rule.matches("rm -rf /tmp"));
    }
}
```

```java
package com.example.shelldetector.model;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class RiskLevelTest {

    @Test
    void testRiskLevelOrder() {
        assertTrue(RiskLevel.DANGER.isHigherOrEqualTo(RiskLevel.RISK));
        assertTrue(RiskLevel.RISK.isHigherOrEqualTo(RiskLevel.SAFE));
        assertTrue(RiskLevel.DANGER.isHigherOrEqualTo(RiskLevel.DANGER));
        assertFalse(RiskLevel.SAFE.isHigherOrEqualTo(RiskLevel.RISK));
    }
}
```

- [ ] **Step 4: 运行测试验证**

运行: `mvn test`
预期: 所有测试通过

---

### Task 6: ANTLR Bash 语法文件

**Files:**
- Create: `src/main/resources/antlr/BashLexer.g4`
- Create: `src/main/resources/antlr/BashParser.g4`

- [ ] **Step 1: 下载成熟的 Bash 语法文件**

我们使用 antlr/grammars-v4 仓库中的完整 Bash 语法：

```bash
cd src/main/resources/antlr
curl -L -o BashLexer.g4 https://raw.githubusercontent.com/antlr/grammars-v4/master/bash/BashLexer.g4
curl -L -o BashParser.g4 https://raw.githubusercontent.com/antlr/grammars-v4/master/bash/BashParser.g4
```

如果无法访问 GitHub，使用以下简化版语法（仅用于演示，功能有限）：

**简化版 BashLexer.g4:**
```g4
lexer grammar BashLexer;

WHITESPACE: [ \t]+ -> skip;
NEWLINE: '\r'? '\n';

PIPE: '|';
ANDAND: '&&';
OROR: '||';
SEMICOLON: ';';
AMPERSAND: '&';

LPAREN: '(';
RPAREN: ')';
LBRACE: '{';
RBRACE: '}';

REDIRECT_OUT: '>' -> mode(REDIRECT_MODE);
REDIRECT_APPEND: '>>' -> mode(REDIRECT_MODE);
REDIRECT_IN: '<' -> mode(REDIRECT_MODE);

WORD: ( ~[ \t\n\r(){}|&;<>] | ESCAPED_CHAR )+;
fragment ESCAPED_CHAR: '\\' .;

mode REDIRECT_MODE;
REDIRECT_WHITESPACE: [ \t]+ -> skip;
FILENAME: ( ~[ \t\n\r] | ESCAPED_CHAR )+ -> mode(DEFAULT_MODE);
```

**简化版 BashParser.g4:**
```g4
parser grammar BashParser;
options { tokenVocab=BashLexer; }

parse: commandList EOF;

commandList: command (SEMICOLON command)* SEMICOLON?;

command: pipeline ( (ANDAND | OROR) pipeline )*;

pipeline: simpleCommand (PIPE simpleCommand)*;

simpleCommand: WORD+;
```

- [ ] **Step 2: 编译生成 ANTLR 类**

运行: `mvn antlr4:generate`
预期: 在 target/generated-sources/antlr4 下生成 BashLexer.java, BashParser.java 等

---

### Task 7: Core 层 - RuleMatcher 规则匹配器

**Files:**
- Create: `src/main/java/com/example/shelldetector/core/RuleMatcher.java`
- Test: `src/test/java/com/example/shelldetector/core/RuleMatcherTest.java`

- [ ] **Step 1: 创建 RuleMatcher 类**

```java
package com.example.shelldetector.core;

import com.example.shelldetector.model.Rule;
import com.example.shelldetector.model.RuleType;

import java.util.ArrayList;
import java.util.List;

public class RuleMatcher {

    public List<Rule> matchWhitelist(String command, List<Rule> rules) {
        List<Rule> matched = new ArrayList<>();
        for (Rule rule : rules) {
            if (rule.getType() == RuleType.WHITELIST && rule.matches(command)) {
                matched.add(rule);
            }
        }
        return matched;
    }

    public List<Rule> matchBlacklist(String command, List<Rule> rules) {
        List<Rule> matched = new ArrayList<>();
        for (Rule rule : rules) {
            if (rule.getType() == RuleType.BLACKLIST && rule.matches(command)) {
                matched.add(rule);
            }
        }
        return matched;
    }

    public boolean isEntireCommandWhitelisted(String entireCommand, List<Rule> rules) {
        return !matchWhitelist(entireCommand, rules).isEmpty();
    }

    public boolean areAllCommandsWhitelisted(List<String> commands, List<Rule> rules) {
        if (commands.isEmpty()) {
            return false;
        }
        for (String cmd : commands) {
            if (matchWhitelist(cmd, rules).isEmpty()) {
                return false;
            }
        }
        return true;
    }
}
```

- [ ] **Step 2: 编写测试**

```java
package com.example.shelldetector.core;

import com.example.shelldetector.model.Rule;
import com.example.shelldetector.model.RuleType;
import org.junit.jupiter.api.Test;
import java.util.Arrays;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

class RuleMatcherTest {

    @Test
    void testMatchWhitelist() {
        RuleMatcher matcher = new RuleMatcher();
        Rule whitelistRule = Rule.builder()
                .pattern("ls.*")
                .type(RuleType.WHITELIST)
                .build();
        Rule blacklistRule = Rule.builder()
                .pattern("rm.*")
                .type(RuleType.BLACKLIST)
                .build();
        List<Rule> rules = Arrays.asList(whitelistRule, blacklistRule);

        List<Rule> matched = matcher.matchWhitelist("ls -la", rules);
        assertEquals(1, matched.size());
        assertEquals(RuleType.WHITELIST, matched.get(0).getType());
    }

    @Test
    void testAreAllCommandsWhitelisted() {
        RuleMatcher matcher = new RuleMatcher();
        Rule lsRule = Rule.builder().pattern("ls.*").whitelist().build();
        Rule catRule = Rule.builder().pattern("cat.*").whitelist().build();
        List<Rule> rules = Arrays.asList(lsRule, catRule);

        assertTrue(matcher.areAllCommandsWhitelisted(Arrays.asList("ls -la", "cat file"), rules));
        assertFalse(matcher.areAllCommandsWhitelisted(Arrays.asList("ls -la", "rm file"), rules));
        assertFalse(matcher.areAllCommandsWhitelisted(Arrays.asList(), rules));
    }
}
```

- [ ] **Step 3: 运行测试**

运行: `mvn test`
预期: 所有测试通过

---

### Task 8: Core 层 - RiskEvaluator 风险评估器

**Files:**
- Create: `src/main/java/com/example/shelldetector/core/RiskEvaluator.java`
- Test: `src/test/java/com/example/shelldetector/core/RiskEvaluatorTest.java`

- [ ] **Step 1: 创建 RiskEvaluator 类**

```java
package com.example.shelldetector.core;

import com.example.shelldetector.model.RiskLevel;
import com.example.shelldetector.model.Rule;

import java.util.List;

public class RiskEvaluator {

    public RiskLevel evaluateHighestRisk(List<Rule> matchedRules) {
        RiskLevel highest = RiskLevel.SAFE;
        for (Rule rule : matchedRules) {
            if (rule.getRiskLevel().isHigherOrEqualTo(highest)) {
                highest = rule.getRiskLevel();
            }
        }
        return highest;
    }

    public boolean shouldBlock(RiskLevel riskLevel, RiskLevel threshold) {
        return riskLevel.isHigherOrEqualTo(threshold);
    }
}
```

- [ ] **Step 2: 编写测试**

```java
package com.example.shelldetector.core;

import com.example.shelldetector.model.RiskLevel;
import com.example.shelldetector.model.Rule;
import org.junit.jupiter.api.Test;
import java.util.Arrays;
import static org.junit.jupiter.api.Assertions.*;

class RiskEvaluatorTest {

    @Test
    void testEvaluateHighestRisk() {
        RiskEvaluator evaluator = new RiskEvaluator();
        Rule safeRule = Rule.builder().riskLevel(RiskLevel.SAFE).build();
        Rule riskRule = Rule.builder().riskLevel(RiskLevel.RISK).build();
        Rule dangerRule = Rule.builder().riskLevel(RiskLevel.DANGER).build();

        RiskLevel highest = evaluator.evaluateHighestRisk(Arrays.asList(safeRule, riskRule, dangerRule));
        assertEquals(RiskLevel.DANGER, highest);
    }

    @Test
    void testShouldBlock() {
        RiskEvaluator evaluator = new RiskEvaluator();

        assertTrue(evaluator.shouldBlock(RiskLevel.DANGER, RiskLevel.RISK));
        assertTrue(evaluator.shouldBlock(RiskLevel.RISK, RiskLevel.RISK));
        assertFalse(evaluator.shouldBlock(RiskLevel.SAFE, RiskLevel.RISK));
    }
}
```

- [ ] **Step 3: 运行测试**

运行: `mvn test`
预期: 所有测试通过

---

### Task 9: Parser 层 - Shell 命令提取器

**Files:**
- Create: `src/main/java/com/example/shelldetector/parser/ShellAstListener.java`
- Create: `src/main/java/com/example/shelldetector/parser/ShellCommandExtractor.java`
- Test: `src/test/java/com/example/shelldetector/parser/ShellCommandExtractorTest.java`

- [ ] **Step 1: 创建 ShellAstListener**

注意：根据实际生成的 ANTLR 类包名调整 import。假设生成在 `com.example.shelldetector.parser.antlr` 包下。

```java
package com.example.shelldetector.parser;

import com.example.shelldetector.parser.antlr.BashParser;
import com.example.shelldetector.parser.antlr.BashParserBaseListener;

import java.util.ArrayList;
import java.util.List;

public class ShellAstListener extends BashParserBaseListener {
    private List<String> commands = new ArrayList<>();
    private StringBuilder currentCommand = new StringBuilder();
    private boolean inSimpleCommand = false;

    @Override
    public void enterSimpleCommand(BashParser.SimpleCommandContext ctx) {
        inSimpleCommand = true;
        currentCommand = new StringBuilder();
    }

    @Override
    public void exitSimpleCommand(BashParser.SimpleCommandContext ctx) {
        inSimpleCommand = false;
        String cmd = currentCommand.toString().trim();
        if (!cmd.isEmpty()) {
            commands.add(cmd);
        }
        currentCommand = new StringBuilder();
    }

    @Override
    public void visitTerminal(org.antlr.v4.runtime.tree.TerminalNode node) {
        if (inSimpleCommand) {
            if (currentCommand.length() > 0) {
                currentCommand.append(" ");
            }
            currentCommand.append(node.getText());
        }
    }

    public List<String> getCommands() {
        return new ArrayList<>(commands);
    }
}
```

如果使用简化版语法，需要相应调整方法名。

- [ ] **Step 2: 创建 ShellCommandExtractor**

```java
package com.example.shelldetector.parser;

import com.example.shelldetector.exception.ShellParseException;
import com.example.shelldetector.parser.antlr.BashLexer;
import com.example.shelldetector.parser.antlr.BashParser;
import org.antlr.v4.runtime.ANTLRInputStream;
import org.antlr.v4.runtime.CommonTokenStream;
import org.antlr.v4.runtime.tree.ParseTreeWalker;

import java.util.Collections;
import java.util.List;

public class ShellCommandExtractor {

    public List<String> extractCommands(String shellCommand) {
        if (shellCommand == null || shellCommand.trim().isEmpty()) {
            return Collections.emptyList();
        }

        try {
            ANTLRInputStream input = new ANTLRInputStream(shellCommand);
            BashLexer lexer = new BashLexer(input);
            CommonTokenStream tokens = new CommonTokenStream(lexer);
            BashParser parser = new BashParser(tokens);

            ShellAstListener listener = new ShellAstListener();
            ParseTreeWalker walker = new ParseTreeWalker();
            walker.walk(listener, parser.parse());

            return listener.getCommands();
        } catch (Exception e) {
            throw new ShellParseException("Failed to parse shell command: " + shellCommand, e);
        }
    }
}
```

- [ ] **Step 3: 编写测试**

```java
package com.example.shelldetector.parser;

import org.junit.jupiter.api.Test;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

class ShellCommandExtractorTest {

    private ShellCommandExtractor extractor = new ShellCommandExtractor();

    @Test
    void testExtractSimpleCommand() {
        List<String> commands = extractor.extractCommands("ls -la");
        assertEquals(1, commands.size());
        assertTrue(commands.get(0).contains("ls"));
    }

    @Test
    void testExtractPipeline() {
        List<String> commands = extractor.extractCommands("cat /etc/passwd | grep root");
        assertEquals(2, commands.size());
    }

    @Test
    void testExtractMultipleCommands() {
        List<String> commands = extractor.extractCommands("ls -la; echo hello");
        assertEquals(2, commands.size());
    }

    @Test
    void testExtractEmptyCommand() {
        List<String> commands = extractor.extractCommands("");
        assertTrue(commands.isEmpty());
    }
}
```

- [ ] **Step 4: 运行测试**

运行: `mvn test`
预期: 所有测试通过

---

### Task 10: Core 层 - DetectionEngine 检测引擎

**Files:**
- Create: `src/main/java/com/example/shelldetector/core/DetectionEngine.java`
- Test: `src/test/java/com/example/shelldetector/core/DetectionEngineTest.java`

- [ ] **Step 1: 创建 DetectionEngine 类**

```java
package com.example.shelldetector.core;

import com.example.shelldetector.config.DetectionConfig;
import com.example.shelldetector.exception.ShellParseException;
import com.example.shelldetector.model.DetectionResult;
import com.example.shelldetector.model.RiskLevel;
import com.example.shelldetector.model.Rule;
import com.example.shelldetector.parser.ShellCommandExtractor;

import java.util.ArrayList;
import java.util.List;

public class DetectionEngine {
    private final DetectionConfig config;
    private final RuleMatcher ruleMatcher;
    private final RiskEvaluator riskEvaluator;
    private final ShellCommandExtractor commandExtractor;

    public DetectionEngine(DetectionConfig config) {
        this.config = config;
        this.ruleMatcher = new RuleMatcher();
        this.riskEvaluator = new RiskEvaluator();
        this.commandExtractor = new ShellCommandExtractor();
    }

    public DetectionResult detect(String entireCommand, List<Rule> rules) {
        DetectionResult.Builder resultBuilder = DetectionResult.builder();

        try {
            List<String> commands = commandExtractor.extractCommands(entireCommand);

            if (commands.isEmpty()) {
                return resultBuilder.passed(true).build();
            }

            if (ruleMatcher.isEntireCommandWhitelisted(entireCommand, rules)) {
                return resultBuilder.passed(true).build();
            }

            if (ruleMatcher.areAllCommandsWhitelisted(commands, rules)) {
                return resultBuilder.passed(true).build();
            }

            List<Rule> allMatchedRules = new ArrayList<>();
            for (String cmd : commands) {
                List<Rule> matched = ruleMatcher.matchBlacklist(cmd, rules);
                allMatchedRules.addAll(matched);
                for (Rule rule : matched) {
                    resultBuilder.addMatchedRule(rule);
                }
            }

            RiskLevel highestRisk = riskEvaluator.evaluateHighestRisk(allMatchedRules);
            boolean shouldBlock = riskEvaluator.shouldBlock(highestRisk, config.getThreshold());

            if (shouldBlock) {
                resultBuilder.passed(false)
                        .highestRiskLevel(highestRisk)
                        .blockReason("Command exceeded risk threshold: " + highestRisk.getDescription());
            }

        } catch (ShellParseException e) {
            if (config.isFailOnParseError()) {
                throw e;
            }
            resultBuilder.passed(true);
        }

        return resultBuilder.build();
    }
}
```

- [ ] **Step 2: 编写测试**

```java
package com.example.shelldetector.core;

import com.example.shelldetector.config.DetectionConfig;
import com.example.shelldetector.model.DetectionResult;
import com.example.shelldetector.model.RiskLevel;
import com.example.shelldetector.model.Rule;
import org.junit.jupiter.api.Test;
import java.util.Arrays;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

class DetectionEngineTest {

    @Test
    void testDangerousCommandBlocked() {
        DetectionConfig config = DetectionConfig.builder().threshold(RiskLevel.RISK).build();
        DetectionEngine engine = new DetectionEngine(config);

        Rule rule = Rule.builder()
                .pattern("rm\\s+-rf")
                .blacklist()
                .riskLevel(RiskLevel.DANGER)
                .build();
        List<Rule> rules = Arrays.asList(rule);

        DetectionResult result = engine.detect("rm -rf /tmp", rules);
        assertFalse(result.isPassed());
        assertEquals(RiskLevel.DANGER, result.getHighestRiskLevel());
    }

    @Test
    void testEntireCommandWhitelisted() {
        DetectionConfig config = DetectionConfig.builder().threshold(RiskLevel.RISK).build();
        DetectionEngine engine = new DetectionEngine(config);

        Rule whitelistRule = Rule.builder().pattern("ls -la").whitelist().build();
        Rule blacklistRule = Rule.builder().pattern("rm.*").blacklist().riskLevel(RiskLevel.DANGER).build();
        List<Rule> rules = Arrays.asList(whitelistRule, blacklistRule);

        DetectionResult result = engine.detect("ls -la", rules);
        assertTrue(result.isPassed());
    }

    @Test
    void testAllCommandsWhitelisted() {
        DetectionConfig config = DetectionConfig.builder().threshold(RiskLevel.RISK).build();
        DetectionEngine engine = new DetectionEngine(config);

        Rule lsRule = Rule.builder().pattern("ls.*").whitelist().build();
        Rule catRule = Rule.builder().pattern("cat.*").whitelist().build();
        List<Rule> rules = Arrays.asList(lsRule, catRule);

        DetectionResult result = engine.detect("ls -la; cat file", rules);
        assertTrue(result.isPassed());
    }
}
```

- [ ] **Step 3: 运行测试**

运行: `mvn test`
预期: 所有测试通过

---

### Task 11: 内置规则

**Files:**
- Create: `src/main/resources/builtin-rules.json`
- Create: `src/main/java/com/example/shelldetector/builtin/BuiltinRules.java`

- [ ] **Step 1: 创建内置规则 JSON**

```json
{
  "version": "1.0",
  "rules": [
    {
      "id": "builtin-rm-rf-root",
      "name": "rm -rf root",
      "type": "BLACKLIST",
      "pattern": "rm\\s+.*-rf.*\\s+/",
      "riskLevel": "DANGER",
      "description": "递归删除根目录",
      "enabled": true
    },
    {
      "id": "builtin-mkfs",
      "name": "mkfs",
      "type": "BLACKLIST",
      "pattern": "mkfs\\..*",
      "riskLevel": "DANGER",
      "description": "格式化文件系统",
      "enabled": true
    },
    {
      "id": "builtin-dd",
      "name": "dd dangerous",
      "type": "BLACKLIST",
      "pattern": "dd.*of=/dev/",
      "riskLevel": "DANGER",
      "description": "dd写入设备",
      "enabled": true
    },
    {
      "id": "builtin-reboot",
      "name": "reboot",
      "type": "BLACKLIST",
      "pattern": "reboot|shutdown|init\\s+0|init\\s+6|systemctl.*poweroff|systemctl.*reboot|halt|poweroff",
      "riskLevel": "DANGER",
      "description": "系统重启/关机",
      "enabled": true
    },
    {
      "id": "builtin-rm-rf",
      "name": "rm -rf",
      "type": "BLACKLIST",
      "pattern": "rm\\s+.*-rf",
      "riskLevel": "RISK",
      "description": "递归删除",
      "enabled": true
    },
    {
      "id": "builtin-cp-mv",
      "name": "cp/mv",
      "type": "BLACKLIST",
      "pattern": "cp\\s+-f|mv\\s+",
      "riskLevel": "RISK",
      "description": "复制/移动文件",
      "enabled": true
    },
    {
      "id": "builtin-touch-mkdir",
      "name": "touch/mkdir",
      "type": "BLACKLIST",
      "pattern": "touch\\s+|mkdir\\s+-p",
      "riskLevel": "RISK",
      "description": "创建文件/目录",
      "enabled": true
    },
    {
      "id": "builtin-sed-awk-perl",
      "name": "sed/awk/perl in-place",
      "type": "BLACKLIST",
      "pattern": "sed\\s+-i|awk\\s+-i.*inplace|perl\\s+-i",
      "riskLevel": "RISK",
      "description": "原地修改文件",
      "enabled": true
    },
    {
      "id": "builtin-chmod",
      "name": "chmod dangerous",
      "type": "BLACKLIST",
      "pattern": "chmod\\s+777|chmod\\s+-R",
      "riskLevel": "RISK",
      "description": "危险权限修改",
      "enabled": true
    },
    {
      "id": "builtin-chown",
      "name": "chown/chgrp",
      "type": "BLACKLIST",
      "pattern": "chown\\s+-R|chgrp\\s+-R",
      "riskLevel": "RISK",
      "description": "递归修改所有者",
      "enabled": true
    },
    {
      "id": "builtin-kill",
      "name": "kill -9",
      "type": "BLACKLIST",
      "pattern": "kill\\s+-9|pkill\\s+-9|killall\\s+-9",
      "riskLevel": "RISK",
      "description": "强制终止进程",
      "enabled": true
    },
    {
      "id": "builtin-ls",
      "name": "ls",
      "type": "WHITELIST",
      "pattern": "^\\s*ls\\b",
      "riskLevel": "SAFE",
      "description": "查看目录",
      "enabled": true
    },
    {
      "id": "builtin-cat",
      "name": "cat",
      "type": "WHITELIST",
      "pattern": "^\\s*cat\\b",
      "riskLevel": "SAFE",
      "description": "查看文件内容",
      "enabled": true
    },
    {
      "id": "builtin-echo",
      "name": "echo/printf",
      "type": "WHITELIST",
      "pattern": "^\\s*echo\\b|^\\s*printf\\b",
      "riskLevel": "SAFE",
      "description": "输出文本",
      "enabled": true
    },
    {
      "id": "builtin-info",
      "name": "info commands",
      "type": "WHITELIST",
      "pattern": "^\\s*pwd\\b|^\\s*whoami\\b|^\\s*id\\b|^\\s*date\\b|^\\s*uptime\\b",
      "riskLevel": "SAFE",
      "description": "系统信息查询",
      "enabled": true
    },
    {
      "id": "builtin-process-view",
      "name": "process view",
      "type": "WHITELIST",
      "pattern": "^\\s*ps\\b|^\\s*top\\b",
      "riskLevel": "SAFE",
      "description": "进程查看",
      "enabled": true
    },
    {
      "id": "builtin-file-view",
      "name": "file view",
      "type": "WHITELIST",
      "pattern": "^\\s*head\\b|^\\s*tail\\b|^\\s*less\\b|^\\s*more\\b",
      "riskLevel": "SAFE",
      "description": "文件内容查看",
      "enabled": true
    },
    {
      "id": "builtin-search",
      "name": "search",
      "type": "WHITELIST",
      "pattern": "^\\s*grep\\b|^\\s*find\\b",
      "riskLevel": "SAFE",
      "description": "搜索",
      "enabled": true
    }
  ]
}
```

- [ ] **Step 2: 创建 BuiltinRules 类**

```java
package com.example.shelldetector.builtin;

import com.example.shelldetector.model.Rule;
import com.example.shelldetector.persistence.RuleLoader;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class BuiltinRules {
    private static final String BUILTIN_RESOURCES = "/builtin-rules.json";
    private static List<Rule> cachedRules;

    public static List<Rule> getRules() {
        if (cachedRules == null) {
            cachedRules = loadRules();
        }
        return Collections.unmodifiableList(cachedRules);
    }

    private static List<Rule> loadRules() {
        try (InputStream is = BuiltinRules.class.getResourceAsStream(BUILTIN_RESOURCES)) {
            if (is == null) {
                return new ArrayList<>();
            }
            return RuleLoader.loadFromJson(is);
        } catch (IOException e) {
            return new ArrayList<>();
        }
    }
}
```

---

### Task 12: Persistence 层 - JSON 持久化

**Files:**
- Create: `src/main/java/com/example/shelldetector/persistence/RuleLoader.java`
- Create: `src/main/java/com/example/shelldetector/persistence/RuleSaver.java`
- Test: `src/test/java/com/example/shelldetector/persistence/RulePersistenceTest.java`

- [ ] **Step 1: 创建 RuleLoader**

```java
package com.example.shelldetector.persistence;

import com.example.shelldetector.exception.RulePersistenceException;
import com.example.shelldetector.model.Rule;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class RuleLoader {
    private static final ObjectMapper objectMapper = new ObjectMapper();

    public static List<Rule> loadFromJson(File file) {
        try {
            Map<String, Object> data = objectMapper.readValue(file, new TypeReference<Map<String, Object>>() {});
            return extractRules(data);
        } catch (IOException e) {
            throw new RulePersistenceException("Failed to load rules from " + file, e);
        }
    }

    public static List<Rule> loadFromJson(String path) {
        return loadFromJson(new File(path));
    }

    public static List<Rule> loadFromJson(InputStream is) {
        try {
            Map<String, Object> data = objectMapper.readValue(is, new TypeReference<Map<String, Object>>() {});
            return extractRules(data);
        } catch (IOException e) {
            throw new RulePersistenceException("Failed to load rules from stream", e);
        }
    }

    @SuppressWarnings("unchecked")
    private static List<Rule> extractRules(Map<String, Object> data) {
        List<Rule> rules = new ArrayList<>();
        List<Map<String, Object>> ruleMaps = (List<Map<String, Object>>) data.get("rules");
        if (ruleMaps != null) {
            for (Map<String, Object> rm : ruleMaps) {
                Rule.Builder builder = Rule.builder()
                        .id((String) rm.get("id"))
                        .name((String) rm.get("name"))
                        .pattern((String) rm.get("pattern"))
                        .description((String) rm.get("description"))
                        .enabled(Boolean.TRUE.equals(rm.get("enabled")));

                String typeStr = (String) rm.get("type");
                if ("WHITELIST".equals(typeStr)) {
                    builder.whitelist();
                } else {
                    builder.blacklist();
                }

                String riskStr = (String) rm.get("riskLevel");
                if (riskStr != null) {
                    builder.riskLevel(com.example.shelldetector.model.RiskLevel.valueOf(riskStr));
                }

                rules.add(builder.build());
            }
        }
        return rules;
    }
}
```

- [ ] **Step 2: 创建 RuleSaver**

```java
package com.example.shelldetector.persistence;

import com.example.shelldetector.exception.RulePersistenceException;
import com.example.shelldetector.model.Rule;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class RuleSaver {
    private static final ObjectMapper objectMapper = new ObjectMapper();

    public static void saveToJson(List<Rule> rules, File file) {
        try {
            Map<String, Object> data = new HashMap<>();
            data.put("version", "1.0");
            data.put("rules", rules);
            objectMapper.writerWithDefaultPrettyPrinter().writeValue(file, data);
        } catch (IOException e) {
            throw new RulePersistenceException("Failed to save rules to " + file, e);
        }
    }

    public static void saveToJson(List<Rule> rules, String path) {
        saveToJson(rules, new File(path));
    }
}
```

- [ ] **Step 3: 编写测试**

```java
package com.example.shelldetector.persistence;

import com.example.shelldetector.model.Rule;
import com.example.shelldetector.model.RiskLevel;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.io.File;
import java.util.Arrays;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

class RulePersistenceTest {

    @TempDir
    File tempDir;

    @Test
    void testSaveAndLoadRules() {
        Rule rule1 = Rule.builder()
                .id("test-1")
                .name("test rule 1")
                .blacklist()
                .pattern("rm.*")
                .riskLevel(RiskLevel.DANGER)
                .build();
        Rule rule2 = Rule.builder()
                .id("test-2")
                .name("test rule 2")
                .whitelist()
                .pattern("ls.*")
                .riskLevel(RiskLevel.SAFE)
                .build();
        List<Rule> original = Arrays.asList(rule1, rule2);

        File file = new File(tempDir, "rules.json");
        RuleSaver.saveToJson(original, file);

        List<Rule> loaded = RuleLoader.loadFromJson(file);
        assertEquals(2, loaded.size());
        assertEquals("test-1", loaded.get(0).getId());
    }
}
```

- [ ] **Step 4: 运行测试**

运行: `mvn test`
预期: 所有测试通过

---

### Task 13: ShellDetector 门面类和 Fluent API

**Files:**
- Create: `src/main/java/com/example/shelldetector/ShellDetector.java`
- Test: `src/test/java/com/example/shelldetector/ShellDetectorTest.java`

- [ ] **Step 1: 创建 ShellDetector 类**

```java
package com.example.shelldetector;

import com.example.shelldetector.builtin.BuiltinRules;
import com.example.shelldetector.config.DetectionConfig;
import com.example.shelldetector.core.DetectionEngine;
import com.example.shelldetector.model.DetectionResult;
import com.example.shelldetector.model.RiskLevel;
import com.example.shelldetector.model.Rule;
import com.example.shelldetector.persistence.RuleLoader;
import com.example.shelldetector.persistence.RuleSaver;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class ShellDetector {
    private final DetectionConfig config;
    private final DetectionEngine engine;
    private final Map<String, Rule> rules;

    private ShellDetector(Builder builder) {
        this.config = builder.config;
        this.engine = new DetectionEngine(config);
        this.rules = new ConcurrentHashMap<>();
        for (Rule rule : builder.rules) {
            this.rules.put(rule.getId(), rule);
        }
    }

    public DetectionResult detect(String command) {
        return engine.detect(command, new ArrayList<>(rules.values()));
    }

    public void addRule(Rule rule) {
        rules.put(rule.getId(), rule);
    }

    public void removeRule(String ruleId) {
        rules.remove(ruleId);
    }

    public void updateRule(Rule rule) {
        rules.put(rule.getId(), rule);
    }

    public Rule getRule(String ruleId) {
        return rules.get(ruleId);
    }

    public List<Rule> getRules() {
        return new ArrayList<>(rules.values());
    }

    public void saveRulesToJson(String path) {
        RuleSaver.saveToJson(getRules(), path);
    }

    public void saveRulesToJson(File file) {
        RuleSaver.saveToJson(getRules(), file);
    }

    public static ShellDetector createDefault() {
        return builder().withDefaultRules().build();
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private DetectionConfig config = DetectionConfig.builder().build();
        private List<Rule> rules = new ArrayList<>();

        public Builder withConfig(DetectionConfig config) {
            this.config = config;
            return this;
        }

        public Builder withThreshold(RiskLevel threshold) {
            this.config = DetectionConfig.builder().threshold(threshold).build();
            return this;
        }

        public Builder withDefaultRules() {
            this.rules.addAll(BuiltinRules.getRules());
            return this;
        }

        public Builder withRules(List<Rule> rules) {
            this.rules.addAll(rules);
            return this;
        }

        public Builder withRule(Rule rule) {
            this.rules.add(rule);
            return this;
        }

        public Builder withRulesFromJson(String path) {
            this.rules.addAll(RuleLoader.loadFromJson(path));
            return this;
        }

        public Builder withRulesFromJson(File file) {
            this.rules.addAll(RuleLoader.loadFromJson(file));
            return this;
        }

        public ShellDetector build() {
            return new ShellDetector(this);
        }
    }
}
```

- [ ] **Step 2: 编写集成测试**

```java
package com.example.shelldetector;

import com.example.shelldetector.model.DetectionResult;
import com.example.shelldetector.model.RiskLevel;
import com.example.shelldetector.model.Rule;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class ShellDetectorTest {

    @Test
    void testSimpleDetection() {
        ShellDetector detector = ShellDetector.builder()
                .withRule(Rule.builder()
                        .id("test-rm")
                        .pattern("rm\\s+-rf")
                        .blacklist()
                        .riskLevel(RiskLevel.DANGER)
                        .build())
                .withThreshold(RiskLevel.RISK)
                .build();

        DetectionResult result = detector.detect("rm -rf /tmp");
        assertFalse(result.isPassed());
    }

    @Test
    void testWhitelistEntireCommand() {
        ShellDetector detector = ShellDetector.builder()
                .withRule(Rule.builder()
                        .id("safe-cmd")
                        .pattern("ls -la /tmp")
                        .whitelist()
                        .build())
                .withRule(Rule.builder()
                        .id("danger-rm")
                        .pattern("rm.*")
                        .blacklist()
                        .riskLevel(RiskLevel.DANGER)
                        .build())
                .withThreshold(RiskLevel.RISK)
                .build();

        DetectionResult result = detector.detect("ls -la /tmp");
        assertTrue(result.isPassed());
    }
}
```

- [ ] **Step 3: 运行所有测试**

运行: `mvn clean test`
预期: 所有测试通过

---

### Task 14: 最终验证和集成测试

**Files:**
- Create: `src/test/java/com/example/shelldetector/IntegrationTest.java`

- [ ] **Step 1: 创建集成测试**

```java
package com.example.shelldetector;

import com.example.shelldetector.model.DetectionResult;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class IntegrationTest {

    @Test
    void testBuiltinRules() {
        ShellDetector detector = ShellDetector.createDefault();

        DetectionResult dangerousResult = detector.detect("rm -rf /");
        assertFalse(dangerousResult.isPassed());

        DetectionResult safeResult = detector.detect("ls -la");
        assertTrue(safeResult.isPassed());
    }

    @Test
    void testPipelineCommands() {
        ShellDetector detector = ShellDetector.createDefault();

        DetectionResult result = detector.detect("cat /etc/passwd | grep root");
        assertTrue(result.isPassed());
    }
}
```

- [ ] **Step 2: 完整构建和测试**

运行: `mvn clean install`
预期: BUILD SUCCESS

---

## 附录：使用示例

### 快速开始

```java
// 使用默认配置和内置规则
ShellDetector detector = ShellDetector.createDefault();
DetectionResult result = detector.detect("rm -rf /");

if (!result.isPassed()) {
    System.out.println("Blocked: " + result.getBlockReason());
}
```

### 自定义配置

```java
ShellDetector detector = ShellDetector.builder()
    .withDefaultRules()
    .withThreshold(RiskLevel.DANGER)  // 只拦截高危
    .withRulesFromJson("my-rules.json")
    .build();
```

### 动态管理规则

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
