package com.example.shelldetector.parser;

import com.example.shelldetector.exception.ShellParseException;

import java.util.List;

/**
 * 简单 Shell 解析器实现
 * <p>
 * 使用现有的 ShellCommandExtractor 作为内部实现，
 * 保持向后兼容的同时实现 ShellParser 接口。
 * </p>
 */
public class SimpleShellParser implements ShellParser {

    private final ShellCommandExtractor extractor;

    /**
     * 默认构造函数
     */
    public SimpleShellParser() {
        this.extractor = new ShellCommandExtractor();
    }

    /**
     * 使用指定的提取器构造
     *
     * @param extractor ShellCommandExtractor 实例
     */
    public SimpleShellParser(ShellCommandExtractor extractor) {
        this.extractor = extractor;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public List<String> extractCommands(String shellCommand) throws ShellParseException {
        return extractor.extractCommands(shellCommand);
    }
}
