package com.example.shelldetector.example;

import com.example.shelldetector.ShellDetector;
import com.example.shelldetector.model.DetectionResult;
import com.example.shelldetector.model.RiskLevel;
import com.example.shelldetector.model.Rule;
import com.example.shelldetector.model.RuleType;
import com.example.shelldetector.parser.ShellCommandExtractor;

import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

/**
 * Shell Detector - 手工验证测试程序
 *
 * <p>使用方法:
 * <pre>{@code
 * # 运行所有测试用例
 * mvn compile exec:java -Dexec.mainClass="com.example.shelldetector.example.ManualTest"
 *
 * # 测试单个命令
 * mvn compile exec:java -Dexec.mainClass="com.example.shelldetector.example.ManualTest" -Dexec.args="rm -rf /tmp"
 *
 * # 交互模式
 * mvn compile exec:java -Dexec.mainClass="com.example.shelldetector.example.ManualTest" -Dexec.args="interactive"
 * }</pre>
 *
 * @see docs/手工测试说明.md 完整的手工测试文档
 */
public class ManualTest {

    private static final String[][] TEST_CASES = {
        // { 命令, 期望是否通过, 描述 }
        {"ls -la", "true", "安全命令 ls"},
        {"cat /etc/passwd", "true", "安全命令 cat"},
        {"rm -rf /tmp", "false", "危险命令 rm -rf"},
        {"echo hello", "true", "普通命令 echo"},
        {"cat /etc/passwd | grep root", "true", "管道命令 - 安全"},
        {"ls -la; rm -rf /tmp", "false", "多个命令 - 含危险"},
        {"ls -la > /tmp/out", "false", "重定向写文件 - 拦截"},
        {"echo '123' > 123.sh", "false", "echo + 重定向写文件 - 拦截"},
        {"echo '123' >> 123.sh", "false", "echo + 追加写文件 - 拦截"},
        {"cat < /etc/passwd", "true", "重定向读文件 - 通过"},
        {"ps -ef | rm -rf xxx.sh", "false", "管道 + rm -rf - 拦截"},
        {"reboot", "false", "高危命令 - 重启"},
        {"mkfs.ext4 /dev/sda1", "false", "高危命令 - 格式化"},
        {"pwd", "true", "白名单命令 - pwd"},
        {"whoami", "true", "白名单命令 - whoami"},
        {"ps aux", "true", "白名单命令 - ps"},
        {"ls -la; cat file", "true", "所有子命令都在白名单"},
        {"ls -la; rm -rf /", "false", "部分子命令在白名单 - 拦截"}
    };

    public static void main(String[] args) {
        System.out.println("========================================");
        System.out.println("   Shell Detector - 手工验证测试");
        System.out.println("========================================");

        ShellDetector detector = ShellDetector.createDefault();

        if (args.length == 0) {
            runAllTests(detector);
        } else if ("interactive".equals(args[0])) {
            runInteractiveMode(detector);
        } else {
            String command = String.join(" ", args);
            detectSingleCommand(detector, command);
        }
    }

    private static void runAllTests(ShellDetector detector) {
        System.out.println("\n【运行所有测试用例】\n");
        int passed = 0, failed = 0;

        for (String[] testCase : TEST_CASES) {
            String cmd = testCase[0];
            boolean expected = Boolean.parseBoolean(testCase[1]);
            String desc = testCase[2];

            DetectionResult result = detector.detect(cmd);
            boolean actual = result.isPassed();

            System.out.printf("  %-40s ", desc);
            if (expected == actual) {
                System.out.println("✓ 通过");
                passed++;
            } else {
                System.out.println("✗ 失败 (期望: " + expected + ", 实际: " + actual + ")");
                if (!actual) {
                    System.out.println("      原因: " + result.getBlockReason());
                }
                failed++;
            }
        }

        System.out.println("\n----------------------------------------");
        System.out.println("  总计: " + (passed + failed));
        System.out.println("  通过: " + passed);
        System.out.println("  失败: " + failed);
        System.out.println("  通过率: " + (passed + failed > 0 ? (passed * 100 / (passed + failed)) : 0) + "%");
        System.out.println("========================================");

        System.out.println("\n【使用说明】");
        System.out.println("  1. 测试单个命令: mvn exec:java -Dexec.args=\"rm -rf /tmp\"");
        System.out.println("  2. 交互模式:     mvn exec:java -Dexec.args=interactive");
    }

    private static void detectSingleCommand(ShellDetector detector, String command) {
        System.out.println("\n【检测命令】");
        System.out.println("  输入: \"" + command + "\"");

        long start = System.currentTimeMillis();
        DetectionResult result = detector.detect(command);
        long duration = System.currentTimeMillis() - start;

        System.out.println("\n【检测结果】");
        System.out.println("  通过: " + (result.isPassed() ? "✓ 是" : "✗ 否"));
        System.out.println("  耗时: " + duration + "ms");

        if (!result.isPassed()) {
            System.out.println("  拦截原因: " + result.getBlockReason());
            System.out.println("  最高风险等级: " + result.getHighestRiskLevel().getDescription());
        }

        List<Rule> matched = result.getMatchedRules();
        if (!matched.isEmpty()) {
            System.out.println("\n【匹配规则】");
            for (Rule r : matched) {
                System.out.println("  - [" + r.getId() + "] " + r.getName() +
                                   " (" + r.getType() + ", " + r.getRiskLevel().getDescription() + ")");
                System.out.println("    描述: " + r.getDescription());
                System.out.println("    模式: " + r.getPattern());
            }
        }

        ShellCommandExtractor extractor = new ShellCommandExtractor();
        List<String> commands = extractor.extractCommands(command);
        if (!commands.isEmpty()) {
            System.out.println("\n【提取的子命令】");
            for (String c : commands) {
                System.out.println("  - \"" + c + "\"");
                for (Rule r : detector.getRules()) {
                    if (r.matches(c)) {
                        System.out.println("    匹配: " + r.getId() + " (" + r.getType() + ")");
                    }
                }
            }
        }
    }

    private static void runInteractiveMode(ShellDetector detector) {
        System.out.println("\n【交互模式】");
        System.out.println("  输入 'quit' 或 'exit' 退出");
        System.out.println("  输入 'rules' 查看所有规则");
        System.out.println("  输入 'help' 查看帮助");
        System.out.println("----------------------------------------");

        Scanner scanner = new Scanner(System.in);
        while (true) {
            System.out.print("\n> ");
            String line = scanner.nextLine().trim();
            if (line.isEmpty()) continue;

            if ("quit".equals(line) || "exit".equals(line)) {
                System.out.println("再见!");
                break;
            }
            if ("help".equals(line)) {
                printInteractiveHelp();
                continue;
            }
            if ("rules".equals(line)) {
                printAllRules(detector);
                continue;
            }

            detectSingleCommand(detector, line);
        }
        scanner.close();
    }

    private static void printInteractiveHelp() {
        System.out.println("\n【帮助】");
        System.out.println("  help     - 显示帮助");
        System.out.println("  rules    - 显示所有内置规则");
        System.out.println("  quit     - 退出程序");
        System.out.println("  exit     - 退出程序");
        System.out.println("  <命令>   - 检测指定的 shell 命令");
    }

    private static void printAllRules(ShellDetector detector) {
        System.out.println("\n【所有规则】");

        List<Rule> whitelist = new ArrayList<>();
        List<Rule> blacklist = new ArrayList<>();
        for (Rule r : detector.getRules()) {
            if (r.getType() == RuleType.WHITELIST) {
                whitelist.add(r);
            } else {
                blacklist.add(r);
            }
        }

        System.out.println("\n  白名单规则 (" + whitelist.size() + "):");
        for (Rule r : whitelist) {
            System.out.println("    [" + r.getId() + "] " + r.getName() + " - " + r.getDescription());
        }

        System.out.println("\n  黑名单规则 (" + blacklist.size() + "):");
        for (Rule r : blacklist) {
            System.out.println("    [" + r.getId() + "] " + r.getName() +
                               " (" + r.getRiskLevel().getDescription() + ") - " + r.getDescription());
        }
    }
}
