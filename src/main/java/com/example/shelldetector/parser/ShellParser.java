package com.example.shelldetector.parser;

import com.example.shelldetector.exception.ShellParseException;

import java.util.List;

/**
 * Shell 命令解析器接口
 * <p>
 * 定义统一的解析方法，支持多种实现：
 * <ul>
 *     <li>SIMPLE - 手写的简单解析器（默认）</li>
 *     <li>ANTLR - 基于 ANTLR 的完整语法解析器</li>
 * </ul>
 * </p>
 */
public interface ShellParser {

    /**
     * 从 Shell 命令字符串中提取子命令列表
     *
     * @param shellCommand 完整的 Shell 命令字符串
     * @return 子命令列表
     * @throws ShellParseException 如果解析过程出错
     */
    List<String> extractCommands(String shellCommand) throws ShellParseException;
}
