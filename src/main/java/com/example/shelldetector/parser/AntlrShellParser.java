package com.example.shelldetector.parser;

import com.example.shelldetector.exception.ShellParseException;
import com.example.shelldetector.parser.antlr.BashLexer;
import com.example.shelldetector.parser.antlr.BashParser;
import com.example.shelldetector.parser.antlr.BashParserBaseListener;
import org.antlr.v4.runtime.ANTLRInputStream;
import org.antlr.v4.runtime.CommonTokenStream;
import org.antlr.v4.runtime.tree.ParseTreeWalker;

import java.util.ArrayList;
import java.util.List;

/**
 * 基于 ANTLR 的 Shell 解析器实现
 * <p>
 * 使用 ANTLR Bash 语法进行解析，能够更准确地处理复杂的 Shell 语法。
 * </p>
 */
public class AntlrShellParser implements ShellParser {

    /**
     * {@inheritDoc}
     */
    @Override
    public List<String> extractCommands(String shellCommand) throws ShellParseException {
        if (shellCommand == null || shellCommand.trim().isEmpty()) {
            return new ArrayList<>();
        }

        try {
            ANTLRInputStream input = new ANTLRInputStream(shellCommand);
            BashLexer lexer = new BashLexer(input);
            CommonTokenStream tokens = new CommonTokenStream(lexer);
            BashParser parser = new BashParser(tokens);

            // 移除默认错误监听器，添加我们自己的（让语法错误抛出异常）
            lexer.removeErrorListeners();
            parser.removeErrorListeners();
            lexer.addErrorListener(new ThrowingErrorListener());
            parser.addErrorListener(new ThrowingErrorListener());

            CommandExtractorListener listener = new CommandExtractorListener();
            ParseTreeWalker walker = new ParseTreeWalker();
            walker.walk(listener, parser.parse());

            return listener.getCommands();
        } catch (Exception e) {
            throw new ShellParseException("Failed to parse shell command with ANTLR: " + shellCommand, e);
        }
    }

    /**
     * ANTLR 解析监听器，用于从 AST 中提取命令
     */
    private static class CommandExtractorListener extends BashParserBaseListener {

        private final List<String> commands = new ArrayList<>();
        private final StringBuilder currentCommand = new StringBuilder();
        private boolean inSimpleCommand = false;

        @Override
        public void enterSimpleCommand(BashParser.SimpleCommandContext ctx) {
            inSimpleCommand = true;
            currentCommand.setLength(0);
        }

        @Override
        public void exitSimpleCommand(BashParser.SimpleCommandContext ctx) {
            inSimpleCommand = false;
            String cmd = currentCommand.toString().trim();
            if (!cmd.isEmpty()) {
                commands.add(cmd);
            }
            currentCommand.setLength(0);
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

        List<String> getCommands() {
            return new ArrayList<>(commands);
        }
    }

    /**
     * 错误监听器，将 ANTLR 错误转换为异常
     */
    private static class ThrowingErrorListener extends org.antlr.v4.runtime.BaseErrorListener {
        @Override
        public void syntaxError(org.antlr.v4.runtime.Recognizer<?, ?> recognizer,
                               Object offendingSymbol,
                               int line,
                               int charPositionInLine,
                               String msg,
                               org.antlr.v4.runtime.RecognitionException e) {
            throw new ShellParseException("Syntax error at line " + line + ":" + charPositionInLine + " - " + msg, e);
        }
    }
}
