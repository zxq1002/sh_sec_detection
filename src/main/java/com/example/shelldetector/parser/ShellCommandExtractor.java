package com.example.shelldetector.parser;

import com.example.shelldetector.exception.ShellParseException;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Shell 命令提取器 - 将复合命令拆分为子命令
 * <p>
 * 按命令分隔符 [;|&] 分割命令字符串，但保留重定向操作符（>, >>, < 等）在子命令中，
 * 确保后续检测可以看到完整的命令上下文。
 * </p>
 *
 * <p>示例：</p>
 * <pre>{@code
 * "ps -ef | rm -rf xxx.sh"
 *   → ["ps -ef", "rm -rf xxx.sh"]
 *
 * "echo '123' > 123.sh; cat file.txt"
 *   → ["echo '123' > 123.sh", "cat file.txt"]
 * }</pre>
 */
public class ShellCommandExtractor {

    /**
     * 命令分隔符模式：分号(;)、管道符(|)、与操作符(&)
     * <p>
     * 注意：重定向操作符(>, >>, <)不在这里，它们会被保留在子命令中。
     * </p>
     */
    private static final Pattern COMMAND_DELIMITERS = Pattern.compile("[;|&]");

    /**
     * 从复合命令中提取子命令列表
     * <p>
     * 按 [;|&] 分割命令，保留重定向操作符在子命令中，
     * 确保每个子命令都包含完整的上下文信息供后续检测。
     * </p>
     *
     * @param shellCommand 完整的 Shell 命令字符串
     * @return 子命令列表，空命令返回空列表
     * @throws ShellParseException 如果解析过程出错
     */
    public List<String> extractCommands(String shellCommand) {
        if (shellCommand == null || shellCommand.trim().isEmpty()) {
            return Collections.emptyList();
        }

        try {
            List<String> commands = new ArrayList<>();
            String[] parts = COMMAND_DELIMITERS.split(shellCommand);
            for (String part : parts) {
                if (part != null) {
                    String trimmed = part.trim();
                    if (!trimmed.isEmpty()) {
                        commands.add(trimmed);
                    }
                }
            }
            return commands;
        } catch (Exception e) {
            throw new ShellParseException("Failed to parse shell command: " + shellCommand, e);
        }
    }
}
