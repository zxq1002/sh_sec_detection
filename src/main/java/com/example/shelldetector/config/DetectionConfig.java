package com.example.shelldetector.config;

import com.example.shelldetector.model.RiskLevel;
import com.example.shelldetector.parser.ParserType;

import java.io.Serializable;

/**
 * 检测配置 - 配置检测引擎的行为
 * <p>
 * 可配置项：风险阈值、解析失败时的处理策略、解析器类型。
 * </p>
 */
public class DetectionConfig implements Serializable {
    /** 风险阈值，默认为 RISK */
    private RiskLevel threshold = RiskLevel.RISK;
    /** 解析失败时是否抛出异常，默认为 true */
    private boolean failOnParseError = true;
    /** 解析器类型，默认为 SIMPLE */
    private ParserType parserType = ParserType.SIMPLE;

    /**
     * 默认构造函数，使用默认配置
     */
    public DetectionConfig() {
    }

    /**
     * 获取风险阈值
     *
     * @return 当前配置的风险阈值
     */
    public RiskLevel getThreshold() {
        return threshold;
    }

    /**
     * 设置风险阈值
     * <p>
     * 当检测到的风险等级 >= 阈值时，命令将被拦截。
     * </p>
     *
     * @param threshold 风险阈值
     * @throws IllegalArgumentException 如果 threshold 为 null
     */
    public void setThreshold(RiskLevel threshold) {
        if (threshold == null) {
            throw new IllegalArgumentException("Threshold cannot be null");
        }
        this.threshold = threshold;
    }

    /**
     * 解析失败时是否抛出异常
     *
     * @return true 表示解析失败时抛出异常，false 表示解析失败时直接通过
     */
    public boolean isFailOnParseError() {
        return failOnParseError;
    }

    /**
     * 设置解析失败时的处理策略
     *
     * @param failOnParseError true 表示解析失败时抛出异常，false 表示解析失败时直接通过
     */
    public void setFailOnParseError(boolean failOnParseError) {
        this.failOnParseError = failOnParseError;
    }

    /**
     * 获取解析器类型
     *
     * @return 当前配置的解析器类型
     */
    public ParserType getParserType() {
        return parserType;
    }

    /**
     * 设置解析器类型
     *
     * @param parserType 解析器类型
     * @throws IllegalArgumentException 如果 parserType 为 null
     */
    public void setParserType(ParserType parserType) {
        if (parserType == null) {
            throw new IllegalArgumentException("ParserType cannot be null");
        }
        this.parserType = parserType;
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
     * Fluent Builder - 用于构建 DetectionConfig 实例
     */
    public static class Builder {
        private DetectionConfig config = new DetectionConfig();

        /**
         * 设置风险阈值
         *
         * @param threshold 风险阈值
         * @return Builder 实例
         * @throws IllegalArgumentException 如果 threshold 为 null
         */
        public Builder threshold(RiskLevel threshold) {
            if (threshold == null) {
                throw new IllegalArgumentException("Threshold cannot be null");
            }
            config.threshold = threshold;
            return this;
        }

        /**
         * 设置解析失败时的处理策略
         *
         * @param failOnParseError true 表示解析失败时抛出异常，false 表示解析失败时直接通过
         * @return Builder 实例
         */
        public Builder failOnParseError(boolean failOnParseError) {
            config.failOnParseError = failOnParseError;
            return this;
        }

        /**
         * 设置解析器类型
         *
         * @param parserType 解析器类型
         * @return Builder 实例
         * @throws IllegalArgumentException 如果 parserType 为 null
         */
        public Builder parserType(ParserType parserType) {
            if (parserType == null) {
                throw new IllegalArgumentException("ParserType cannot be null");
            }
            config.parserType = parserType;
            return this;
        }

        /**
         * 构建 DetectionConfig 实例
         *
         * @return DetectionConfig 实例
         */
        public DetectionConfig build() {
            return config;
        }
    }
}
