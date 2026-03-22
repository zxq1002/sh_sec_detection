package com.example.shelldetector.parser;

import org.junit.jupiter.api.Test;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

/**
 * ShellParser 接口和实现的测试类
 * <p>
 * 测试两种解析器实现的基本功能，并验证向后兼容性。
 * </p>
 */
class ShellParserTest {

    @Test
    void testSimpleParserBasicExtraction() {
        ShellParser parser = new SimpleShellParser();
        List<String> commands = parser.extractCommands("ls -la; cat file");
        assertEquals(2, commands.size());
        assertTrue(commands.get(0).contains("ls"));
        assertTrue(commands.get(1).contains("cat"));
    }

    @Test
    void testAntlrParserBasicExtraction() {
        ShellParser parser = new AntlrShellParser();
        List<String> commands = parser.extractCommands("ls -la");
        assertEquals(1, commands.size());
        assertTrue(commands.get(0).contains("ls"));
    }

    @Test
    void testParserFactoryCreatesSimpleParser() {
        ShellParser parser = ShellParserFactory.createParser(ParserType.SIMPLE);
        assertTrue(parser instanceof SimpleShellParser);
    }

    @Test
    void testParserFactoryCreatesAntlrParser() {
        ShellParser parser = ShellParserFactory.createParser(ParserType.ANTLR);
        assertTrue(parser instanceof AntlrShellParser);
    }

    @Test
    void testParserFactoryCreatesDefaultParser() {
        ShellParser parser = ShellParserFactory.createDefaultParser();
        assertTrue(parser instanceof SimpleShellParser);
    }

    @Test
    void testSimpleParserHandlesQuotes() {
        ShellParser parser = new SimpleShellParser();
        List<String> commands = parser.extractCommands("echo 'hello; world'");
        assertEquals(1, commands.size());
        assertTrue(commands.get(0).contains("hello; world"));
    }

    @Test
    void testSimpleParserHandlesRedirection() {
        ShellParser parser = new SimpleShellParser();
        List<String> commands = parser.extractCommands("ls -la > output.txt");
        assertEquals(1, commands.size());
        assertTrue(commands.get(0).contains("ls"));
    }

    @Test
    void testSimpleParserHandles2and1() {
        ShellParser parser = new SimpleShellParser();
        List<String> commands = parser.extractCommands("command 2>&1");
        assertEquals(1, commands.size());
        assertTrue(commands.get(0).contains("2>&1"));
    }

    @Test
    void testNullCommandReturnsEmptyList() {
        ShellParser parser = new SimpleShellParser();
        List<String> commands = parser.extractCommands(null);
        assertTrue(commands.isEmpty());
    }

    @Test
    void testEmptyCommandReturnsEmptyList() {
        ShellParser parser = new SimpleShellParser();
        List<String> commands = parser.extractCommands("");
        assertTrue(commands.isEmpty());
    }

    @Test
    void testBlankCommandReturnsEmptyList() {
        ShellParser parser = new SimpleShellParser();
        List<String> commands = parser.extractCommands("   ");
        assertTrue(commands.isEmpty());
    }
}
