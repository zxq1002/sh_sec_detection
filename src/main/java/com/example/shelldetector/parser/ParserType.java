package com.example.shelldetector.parser;

/**
 * 解析器类型枚举
 * <p>
 * 用于在配置中指定使用哪种解析器实现。
 * </p>
 */
public enum ParserType {

    /**
     * 简单解析器 - 使用手写的 ShellCommandExtractor
     * <p>
     * 优点：轻量、快速、依赖少、易调试
     * 缺点：语法覆盖有限
     * </p>
     */
    SIMPLE,

    /**
     * ANTLR 解析器 - 使用 ANTLR Bash 语法
     * <p>
     * 优点：语法覆盖完整、解析准确
     * 缺点：依赖 ANTLR runtime、稍重
     * </p>
     */
    ANTLR
}
