package com.example.shelldetector.parser;

import com.example.shelldetector.exception.ShellParseException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * ShellCommandExtractor 测试类
 * <p>
 * 测试命令提取器的功能，包括：
 * - 按 [;|&] 分割命令
 * - 保留重定向操作符
 * - 空命令处理
 * - 异常处理
 * </p>
 */
class ShellCommandExtractorTest {

    private ShellCommandExtractor extractor;

    @BeforeEach
    void setUp() {
        extractor = new ShellCommandExtractor();
    }

    @Test
    void testExtractCommandsWithNull() {
        List<String> result = extractor.extractCommands(null);
        assertTrue(result.isEmpty());
    }

    @Test
    void testExtractCommandsWithEmptyString() {
        List<String> result = extractor.extractCommands("");
        assertTrue(result.isEmpty());
    }

    @Test
    void testExtractCommandsWithBlankString() {
        List<String> result = extractor.extractCommands("   ");
        assertTrue(result.isEmpty());
    }

    @Test
    void testExtractCommandsSingleCommand() {
        List<String> result = extractor.extractCommands("ls -la");
        assertEquals(1, result.size());
        assertEquals("ls -la", result.get(0));
    }

    @Test
    void testExtractCommandsWithSemicolon() {
        List<String> result = extractor.extractCommands("ls -la; echo hello");
        assertEquals(2, result.size());
        assertEquals("ls -la", result.get(0));
        assertEquals("echo hello", result.get(1));
    }

    @Test
    void testExtractCommandsWithPipe() {
        List<String> result = extractor.extractCommands("ps -ef | grep java");
        assertEquals(2, result.size());
        assertEquals("ps -ef", result.get(0));
        assertEquals("grep java", result.get(1));
    }

    @Test
    void testExtractCommandsWithAmpersand() {
        List<String> result = extractor.extractCommands("cmd1 & cmd2");
        assertEquals(2, result.size());
        assertEquals("cmd1", result.get(0));
        assertEquals("cmd2", result.get(1));
    }

    @Test
    void testExtractCommandsWithMultipleDelimiters() {
        List<String> result = extractor.extractCommands("ls -la | grep test; echo done & wait");
        assertEquals(4, result.size());
        assertEquals("ls -la", result.get(0));
        assertEquals("grep test", result.get(1));
        assertEquals("echo done", result.get(2));
        assertEquals("wait", result.get(3));
    }

    @Test
    void testExtractCommandsPreservesWriteRedirection() {
        List<String> result = extractor.extractCommands("echo '123' > 123.sh");
        assertEquals(1, result.size());
        assertEquals("echo '123' > 123.sh", result.get(0));
    }

    @Test
    void testExtractCommandsPreservesAppendRedirection() {
        List<String> result = extractor.extractCommands("echo '123' >> 123.sh");
        assertEquals(1, result.size());
        assertEquals("echo '123' >> 123.sh", result.get(0));
    }

    @Test
    void testExtractCommandsPreservesReadRedirection() {
        List<String> result = extractor.extractCommands("cat < input.txt");
        assertEquals(1, result.size());
        assertEquals("cat < input.txt", result.get(0));
    }

    @Test
    void testExtractCommandsPreservesStderrRedirection() {
        List<String> result = extractor.extractCommands("cmd 2> error.log");
        assertEquals(1, result.size());
        assertEquals("cmd 2> error.log", result.get(0));
    }

    @Test
    void testExtractCommandsPreservesCombinedRedirection() {
        List<String> result = extractor.extractCommands("cmd > output.log 2>&1");
        assertEquals(1, result.size());
        assertEquals("cmd > output.log 2>&1", result.get(0));
    }

    @Test
    void testExtractCommandsWithRedirectionAndPipe() {
        List<String> result = extractor.extractCommands("cat < input.txt | grep pattern > output.txt");
        assertEquals(2, result.size());
        assertEquals("cat < input.txt", result.get(0));
        assertEquals("grep pattern > output.txt", result.get(1));
    }

    @Test
    void testExtractCommandsTrimsWhitespace() {
        List<String> result = extractor.extractCommands("  ls -la  ;  echo hello  ");
        assertEquals(2, result.size());
        assertEquals("ls -la", result.get(0));
        assertEquals("echo hello", result.get(1));
    }

    @Test
    void testExtractCommandsSkipsEmptyParts() {
        List<String> result = extractor.extractCommands(";;ls -la;;echo hello;;");
        assertEquals(2, result.size());
        assertEquals("ls -la", result.get(0));
        assertEquals("echo hello", result.get(1));
    }

    @Test
    void testExtractCommandsWithOnlyDelimiters() {
        List<String> result = extractor.extractCommands(";;||&&");
        assertTrue(result.isEmpty());
    }

    @Test
    void testExtractCommandsWithComplexCommand() {
        List<String> result = extractor.extractCommands(
                "ps -ef | grep java > process.log; " +
                "echo 'done' >> status.log & " +
                "tail -f log.txt"
        );
        assertEquals(4, result.size());
        assertEquals("ps -ef", result.get(0));
        assertEquals("grep java > process.log", result.get(1));
        assertEquals("echo 'done' >> status.log", result.get(2));
        assertEquals("tail -f log.txt", result.get(3));
    }

    @Test
    void testExtractCommandsWithWhitespaceAroundDelimiters() {
        List<String> result = extractor.extractCommands("cmd1 ; cmd2 | cmd3 & cmd4");
        assertEquals(4, result.size());
        assertEquals("cmd1", result.get(0));
        assertEquals("cmd2", result.get(1));
        assertEquals("cmd3", result.get(2));
        assertEquals("cmd4", result.get(3));
    }

    @Test
    void testExtractCommandsPreservesAllRedirectionOperators() {
        String command = "cmd 1> stdout.log 2> stderr.log 0< stdin.txt 2>&1";
        List<String> result = extractor.extractCommands(command);
        assertEquals(1, result.size());
        assertEquals(command, result.get(0));
    }

    @Test
    void testExtractCommandsWithQuotedStrings() {
        // 注意：当前实现不处理引号内的分隔符，这是已知的限制
        List<String> result = extractor.extractCommands("echo 'hello; world'");
        // 当前实现会分割成 ["echo 'hello", "world'"]
        assertEquals(2, result.size());
    }
}
