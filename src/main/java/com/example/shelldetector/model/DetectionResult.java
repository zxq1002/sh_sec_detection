package com.example.shelldetector.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * 检测结果 - 封装命令检测的完整结果
 * <p>
 * 包含：是否通过、匹配的规则列表、最高风险等级、拦截原因。
 * 使用不可变设计，通过 Builder 构建实例。
 * </p>
 *
 * <p>使用示例：</p>
 * <pre>{@code
 * DetectionResult result = detector.detect("rm -rf /");
 * if (!result.isPassed()) {
 *     System.out.println("Blocked: " + result.getBlockReason());
 *     System.out.println("Risk level: " + result.getHighestRiskLevel());
 *     System.out.println("Matched rules: " + result.getMatchedRules());
 * }
 * }</pre>
 */
public class DetectionResult implements Serializable {
    @JsonProperty("passed")
    private final boolean passed;

    @JsonProperty("matchedRules")
    private final List<Rule> matchedRules;

    @JsonProperty("highestRiskLevel")
    private final RiskLevel highestRiskLevel;

    @JsonProperty("blockReason")
    private final String blockReason;

    /**
     * 私有构造函数，通过 Builder 创建实例
     *
     * @param builder Builder 对象
     */
    private DetectionResult(Builder builder) {
        this.passed = builder.passed;
        this.matchedRules = Collections.unmodifiableList(new ArrayList<>(builder.matchedRules));
        this.highestRiskLevel = builder.highestRiskLevel;
        this.blockReason = builder.blockReason;
    }

    /**
     * 检测是否通过
     *
     * @return true 表示命令安全，可以执行
     */
    public boolean isPassed() { return passed; }

    /**
     * 获取匹配的规则列表（不可修改）
     *
     * @return 匹配成功的规则列表
     */
    public List<Rule> getMatchedRules() { return matchedRules; }

    /**
     * 获取最高风险等级
     *
     * @return 匹配规则中的最高风险等级
     */
    public RiskLevel getHighestRiskLevel() { return highestRiskLevel; }

    /**
     * 获取拦截原因
     *
     * @return 拦截原因描述，未拦截时返回 null
     */
    public String getBlockReason() { return blockReason; }

    /**
     * 创建 Builder 对象
     *
     * @return Builder 实例
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Fluent Builder - 用于构建 DetectionResult 实例
     */
    public static class Builder {
        private boolean passed = true;
        private List<Rule> matchedRules = new ArrayList<>();
        private RiskLevel highestRiskLevel = RiskLevel.SAFE;
        private String blockReason;

        /**
         * 设置是否通过检测
         */
        public Builder passed(boolean passed) {
            this.passed = passed;
            return this;
        }

        /**
         * 添加匹配的规则
         * <p>
         * 同时自动更新最高风险等级。
         * </p>
         *
         * @param rule 匹配成功的规则
         * @return Builder 实例
         */
        public Builder addMatchedRule(Rule rule) {
            this.matchedRules.add(rule);
            if (rule.getRiskLevel().isHigherOrEqualTo(this.highestRiskLevel)) {
                this.highestRiskLevel = rule.getRiskLevel();
            }
            return this;
        }

        /**
         * 设置最高风险等级
         */
        public Builder highestRiskLevel(RiskLevel level) {
            this.highestRiskLevel = level;
            return this;
        }

        /**
         * 设置拦截原因
         */
        public Builder blockReason(String reason) {
            this.blockReason = reason;
            return this;
        }

        /**
         * 构建 DetectionResult 实例
         *
         * @return DetectionResult 实例
         */
        public DetectionResult build() {
            return new DetectionResult(this);
        }
    }
}
