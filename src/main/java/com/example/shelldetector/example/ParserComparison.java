package com.example.shelldetector.example;

import com.example.shelldetector.parser.AntlrShellParser;
import com.example.shelldetector.parser.SimpleShellParser;
import com.example.shelldetector.parser.ShellParser;
import java.util.List;

/**
 * 两种解析器对比演示工具
 *
 * <p>用于直观展示 SIMPLE 和 ANTLR 两种解析器在处理复杂命令时的差异。
 *
 * <p>运行方式:
 * <pre>{@code
 * mvn compile exec:java -Dexec.mainClass="com.example.shelldetector.example.ParserComparison"
 * }</pre>
 *
 * @see docs/parser_security_analysis.md 详细的安全性分析报告
 */
public class ParserComparison {
    public static void main(String[] args) {
        ShellParser simpleParser = new SimpleShellParser();
        ShellParser antlrParser = new AntlrShellParser();

        String[] testCases = {
            "echo $(rm -rf /)",
            "cat /etc/passwd>out.txt",
            "echo \"Cleaning up with rm -rf\""
        };

        for (String testCase : testCases) {
            System.out.println("--------------------------------------------------");
            System.out.println("Test Case: " + testCase);

            try {
                List<String> simpleResult = simpleParser.extractCommands(testCase);
                System.out.println("SimpleParser Result: " + simpleResult);

                List<String> antlrResult = antlrParser.extractCommands(testCase);
                System.out.println("AntlrParser Result:  " + antlrResult);

                // 解释差异
                if (testCase.contains("$(")) {
                    System.out.println("Explanation: ANTLR recursively extracts commands inside $(), while SimpleParser sees it as one string.");
                } else if (testCase.contains(">") && !testCase.contains(" ")) {
                    System.out.println("Explanation: ANTLR recognizes the redirection token '>' even without spaces.");
                } else if (testCase.contains("\"")) {
                    System.out.println("Explanation: ANTLR understands quotes and can distinguish arguments from actual commands.");
                }
            } catch (Exception e) {
                System.out.println("Error parsing: " + e.getMessage());
            }
        }
        System.out.println("--------------------------------------------------");
    }
}
