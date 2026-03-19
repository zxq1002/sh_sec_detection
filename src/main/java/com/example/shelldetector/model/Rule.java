package com.example.shelldetector.model;

import com.example.shelldetector.exception.InvalidPatternException;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.io.Serializable;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * 检测规则 - 定义白名单或黑名单的匹配模式
 * <p>
 * 每个规则包含：ID、名称、类型(白名单/黑名单)、正则表达式模式、风险等级、描述、启用状态。
 * 支持 JSON 序列化和反序列化，可持久化到文件。
 * </p>
 *
 * <p>使用示例：</p>
 * <pre>{@code
 * // 创建黑名单规则
 * Rule rule = Rule.builder()
 *     .id("my-script")
 *     .name("My Dangerous Script")
 *     .blacklist()
 *     .pattern("./danger\\.sh.*")
 *     .riskLevel(RiskLevel.DANGER)
 *     .description("My custom dangerous script")
 *     .build();
 *
 * // 检测命令是否匹配
 * if (rule.matches("rm -rf /")) {
 *     // 匹配成功
 * }
 * }</pre>
 */
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

    /**
     * 私有构造函数，通过 Builder 创建实例
     */
    private Rule() {
    }

    /**
     * 获取规则ID
     */
    public String getId() { return id; }

    /**
     * 获取规则名称
     */
    public String getName() { return name; }

    /**
     * 获取规则类型（白名单/黑名单）
     */
    public RuleType getType() { return type; }

    /**
     * 获取正则表达式模式字符串
     */
    public String getPattern() { return pattern; }

    /**
     * 获取风险等级
     */
    public RiskLevel getRiskLevel() { return riskLevel; }

    /**
     * 获取规则描述
     */
    public String getDescription() { return description; }

    /**
     * 规则是否启用
     */
    public boolean isEnabled() { return enabled; }

    /**
     * 获取编译后的正则表达式 Pattern 对象
     * <p>
     * 使用懒加载模式，第一次调用时编译并缓存。
     * </p>
     *
     * @return 编译后的 Pattern 对象
     * @throws InvalidPatternException 如果正则表达式语法错误
     */
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

    /**
     * 检测命令是否匹配此规则
     * <p>
     * 使用 find() 方法进行子串匹配，不是全词匹配。
     * 如果规则未启用或 pattern 为 null，返回 false。
     * </p>
     *
     * @param command 待检测的命令字符串
     * @return true 表示匹配成功
     */
    public boolean matches(String command) {
        if (!enabled || pattern == null) {
            return false;
        }
        return getCompiledPattern().matcher(command).find();
    }

    /**
     * 创建 Builder 对象
     *
     * @return Builder 实例
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Fluent Builder - 用于构建 Rule 实例
     */
    public static class Builder {
        private String id;
        private String name;
        private RuleType type = RuleType.BLACKLIST;
        private String pattern;
        private RiskLevel riskLevel = RiskLevel.RISK;
        private String description;
        private boolean enabled = true;

        /**
         * 设置规则ID（必需）
         */
        public Builder id(String id) {
            this.id = id;
            return this;
        }

        /**
         * 设置规则名称
         */
        public Builder name(String name) {
            this.name = name;
            return this;
        }

        /**
         * 设置规则类型
         */
        public Builder type(RuleType type) {
            this.type = type;
            return this;
        }

        /**
         * 设置为白名单规则
         */
        public Builder whitelist() {
            this.type = RuleType.WHITELIST;
            return this;
        }

        /**
         * 设置为黑名单规则（默认）
         */
        public Builder blacklist() {
            this.type = RuleType.BLACKLIST;
            return this;
        }

        /**
         * 设置正则表达式模式（必需）
         */
        public Builder pattern(String pattern) {
            this.pattern = pattern;
            return this;
        }

        /**
         * 设置风险等级（默认：RISK）
         */
        public Builder riskLevel(RiskLevel riskLevel) {
            this.riskLevel = riskLevel;
            return this;
        }

        /**
         * 设置规则描述
         */
        public Builder description(String description) {
            this.description = description;
            return this;
        }

        /**
         * 设置是否启用（默认：true）
         */
        public Builder enabled(boolean enabled) {
            this.enabled = enabled;
            return this;
        }

        /**
         * 构建 Rule 实例
         *
         * @return Rule 实例
         * @throws IllegalArgumentException 如果 id 或 pattern 为空
         */
        public Rule build() {
            if (id == null || id.trim().isEmpty()) {
                throw new IllegalArgumentException("Rule id cannot be null or empty");
            }
            if (pattern == null || pattern.trim().isEmpty()) {
                throw new IllegalArgumentException("Rule pattern cannot be null or empty");
            }
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
