import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * Shell Detector - 手工验证测试程序
 *
 * 使用方法：
 *   javac ManualTest.java
 *   java ManualTest
 *   java ManualTest "rm -rf /tmp"
 *   java ManualTest interactive
 */
public class ManualTest {

    // ========== 简化版核心类（复制自项目代码） ==========

    enum RiskLevel {
        SAFE(0, "安全"),
        RISK(1, "风险"),
        DANGER(2, "高危");

        private final int level;
        private final String description;

        RiskLevel(int level, String description) {
            this.level = level;
            this.description = description;
        }

        public int getLevel() { return level; }
        public String getDescription() { return description; }

        public boolean isHigherOrEqualTo(RiskLevel other) {
            return this.level >= other.level;
        }
    }

    enum RuleType { WHITELIST, BLACKLIST }

    static class Rule {
        private String id;
        private String name;
        private RuleType type;
        private String pattern;
        private transient Pattern compiledPattern;
        private RiskLevel riskLevel;
        private String description;
        private boolean enabled;

        private Rule() {}

        public String getId() { return id; }
        public String getName() { return name; }
        public RuleType getType() { return type; }
        public String getPattern() { return pattern; }
        public RiskLevel getRiskLevel() { return riskLevel; }
        public String getDescription() { return description; }
        public boolean isEnabled() { return enabled; }

        public boolean matches(String command) {
            if (!enabled || pattern == null) return false;
            if (compiledPattern == null) {
                try {
                    compiledPattern = Pattern.compile(pattern);
                } catch (PatternSyntaxException e) {
                    return false;
                }
            }
            return compiledPattern.matcher(command).find();
        }

        public static Builder builder() { return new Builder(); }

        public static class Builder {
            private String id;
            private String name;
            private RuleType type = RuleType.BLACKLIST;
            private String pattern;
            private RiskLevel riskLevel = RiskLevel.RISK;
            private String description;
            private boolean enabled = true;

            public Builder id(String id) { this.id = id; return this; }
            public Builder name(String name) { this.name = name; return this; }
            public Builder type(RuleType type) { this.type = type; return this; }
            public Builder whitelist() { this.type = RuleType.WHITELIST; return this; }
            public Builder blacklist() { this.type = RuleType.BLACKLIST; return this; }
            public Builder pattern(String pattern) { this.pattern = pattern; return this; }
            public Builder riskLevel(RiskLevel level) { this.riskLevel = level; return this; }
            public Builder description(String desc) { this.description = desc; return this; }
            public Builder enabled(boolean enabled) { this.enabled = enabled; return this; }

            public Rule build() {
                if (id == null || id.trim().isEmpty()) {
                    throw new IllegalArgumentException("Rule id cannot be null or empty");
                }
                if (pattern == null || pattern.trim().isEmpty()) {
                    throw new IllegalArgumentException("Rule pattern cannot be null or empty");
                }
                Rule rule = new Rule();
                rule.id = this.id;
                rule.name = this.name;
                rule.type = this.type;
                rule.pattern = this.pattern;
                rule.riskLevel = this.riskLevel;
                rule.description = this.description;
                rule.enabled = this.enabled;
                return rule;
            }
        }
    }

    static class DetectionResult {
        private final boolean passed;
        private final List<Rule> matchedRules;
        private final RiskLevel highestRiskLevel;
        private final String blockReason;

        private DetectionResult(Builder builder) {
            this.passed = builder.passed;
            this.matchedRules = Collections.unmodifiableList(new ArrayList<>(builder.matchedRules));
            this.highestRiskLevel = builder.highestRiskLevel;
            this.blockReason = builder.blockReason;
        }

        public boolean isPassed() { return passed; }
        public List<Rule> getMatchedRules() { return matchedRules; }
        public RiskLevel getHighestRiskLevel() { return highestRiskLevel; }
        public String getBlockReason() { return blockReason; }

        public static Builder builder() { return new Builder(); }

        public static class Builder {
            private boolean passed = true;
            private List<Rule> matchedRules = new ArrayList<>();
            private RiskLevel highestRiskLevel = RiskLevel.SAFE;
            private String blockReason;

            public Builder passed(boolean passed) { this.passed = passed; return this; }
            public Builder addMatchedRule(Rule rule) {
                this.matchedRules.add(rule);
                if (rule.getRiskLevel().isHigherOrEqualTo(this.highestRiskLevel)) {
                    this.highestRiskLevel = rule.getRiskLevel();
                }
                return this;
            }
            public Builder highestRiskLevel(RiskLevel level) { this.highestRiskLevel = level; return this; }
            public Builder blockReason(String reason) { this.blockReason = reason; return this; }
            public DetectionResult build() { return new DetectionResult(this); }
        }
    }

    static class CommandExtractor {
        List<String> extract(String cmd) {
            List<String> result = new ArrayList<>();
            if (cmd == null || cmd.trim().isEmpty()) return result;
            String[] parts = cmd.split("[;|&]");
            for (String p : parts) {
                String trimmed = p.trim();
                if (!trimmed.isEmpty()) result.add(trimmed);
            }
            return result;
        }
    }

    static class ShellDetector {
        private List<Rule> rules = new ArrayList<>();
        private RiskLevel threshold = RiskLevel.RISK;

        ShellDetector withThreshold(RiskLevel l) { threshold = l; return this; }
        void addRule(Rule r) { rules.add(r); }
        List<Rule> getRules() { return new ArrayList<>(rules); }

        boolean isEntireWhitelisted(String cmd) {
            if (cmd == null) return false;
            // 完全依赖白名单规则匹配，无硬编码逻辑
            for (Rule r : rules) {
                if (r.getType() == RuleType.WHITELIST && r.matches(cmd)) {
                    return true;
                }
            }
            return false;
        }

        boolean areAllWhitelisted(List<String> cmds) {
            if (cmds == null || cmds.isEmpty()) return false;
            // 完全依赖白名单规则匹配，无硬编码逻辑
            for (String cmd : cmds) {
                if (cmd == null) return false;
                boolean found = false;
                for (Rule r : rules) {
                    if (r.getType() == RuleType.WHITELIST && r.matches(cmd)) { found = true; break; }
                }
                if (!found) return false;
            }
            return true;
        }

        RiskLevel getHighestRisk(List<String> cmds) {
            RiskLevel highest = RiskLevel.SAFE;
            if (cmds == null) return highest;
            for (String cmd : cmds) {
                for (Rule r : rules) {
                    if (r.getType() == RuleType.BLACKLIST && r.matches(cmd)) {
                        if (r.getRiskLevel().isHigherOrEqualTo(highest)) {
                            highest = r.getRiskLevel();
                        }
                    }
                }
            }
            return highest;
        }

        DetectionResult detect(String cmd) {
            DetectionResult.Builder resultBuilder = DetectionResult.builder();
            CommandExtractor extractor = new CommandExtractor();
            List<String> commands = extractor.extract(cmd);

            if (commands.isEmpty()) {
                return resultBuilder.passed(true).build();
            }
            if (isEntireWhitelisted(cmd)) {
                return resultBuilder.passed(true).build();
            }
            if (areAllWhitelisted(commands)) {
                return resultBuilder.passed(true).build();
            }

            for (String c : commands) {
                for (Rule r : rules) {
                    if (r.getType() == RuleType.BLACKLIST && r.matches(c)) {
                        resultBuilder.addMatchedRule(r);
                    }
                }
            }

            RiskLevel highest = getHighestRisk(commands);
            if (highest.isHigherOrEqualTo(threshold)) {
                resultBuilder.passed(false)
                        .highestRiskLevel(highest)
                        .blockReason("Command exceeded risk threshold: " + highest.getDescription());
            }

            return resultBuilder.build();
        }
    }

    // ========== 内置规则 ==========

    private static ShellDetector createDefaultDetector() {
        ShellDetector detector = new ShellDetector().withThreshold(RiskLevel.RISK);

        // 黑名单规则
        detector.addRule(Rule.builder().id("builtin-rm-rf-root").name("rm -rf root")
                .pattern("rm\\s+.*-rf.*\\s+/").blacklist().riskLevel(RiskLevel.DANGER)
                .description("递归删除根目录").build());
        detector.addRule(Rule.builder().id("builtin-mkfs").name("mkfs")
                .pattern("mkfs\\..*").blacklist().riskLevel(RiskLevel.DANGER)
                .description("格式化文件系统").build());
        detector.addRule(Rule.builder().id("builtin-dd").name("dd dangerous")
                .pattern("dd.*of=/dev/").blacklist().riskLevel(RiskLevel.DANGER)
                .description("dd写入设备").build());
        detector.addRule(Rule.builder().id("builtin-reboot").name("reboot")
                .pattern("reboot|shutdown|init\\s+0|init\\s+6|halt|poweroff")
                .blacklist().riskLevel(RiskLevel.DANGER).description("系统重启/关机").build());
        detector.addRule(Rule.builder().id("builtin-rm-rf").name("rm -rf")
                .pattern("rm\\s+.*-rf").blacklist().riskLevel(RiskLevel.RISK)
                .description("递归删除").build());
        detector.addRule(Rule.builder().id("builtin-cp-mv").name("cp/mv")
                .pattern("cp\\s+-f|mv\\s+").blacklist().riskLevel(RiskLevel.RISK)
                .description("复制/移动文件").build());
        detector.addRule(Rule.builder().id("builtin-touch-mkdir").name("touch/mkdir")
                .pattern("touch\\s+|mkdir\\s+-p").blacklist().riskLevel(RiskLevel.RISK)
                .description("创建文件/目录").build());
        detector.addRule(Rule.builder().id("builtin-sed-awk-perl").name("sed/awk/perl in-place")
                .pattern("sed\\s+-i|awk\\s+-i.*inplace|perl\\s+-i")
                .blacklist().riskLevel(RiskLevel.RISK).description("原地修改文件").build());
        detector.addRule(Rule.builder().id("builtin-chmod").name("chmod dangerous")
                .pattern("chmod\\s+777|chmod\\s+-R").blacklist().riskLevel(RiskLevel.RISK)
                .description("危险权限修改").build());
        detector.addRule(Rule.builder().id("builtin-chown").name("chown/chgrp")
                .pattern("chown\\s+-R|chgrp\\s+-R").blacklist().riskLevel(RiskLevel.RISK)
                .description("递归修改所有者").build());
        detector.addRule(Rule.builder().id("builtin-kill").name("kill -9")
                .pattern("kill\\s+-9|pkill\\s+-9|killall\\s+-9")
                .blacklist().riskLevel(RiskLevel.RISK).description("强制终止进程").build());
        detector.addRule(Rule.builder().id("builtin-file-write").name("file write redirection")
                .pattern("\\s*>\\s*[^\\s]|\\s*1>\\s*[^\\s]|\\s*2>\\s*[^\\s]|\\s*>>\\s*[^\\s]")
                .blacklist().riskLevel(RiskLevel.RISK).description("重定向写文件").build());

        // 白名单规则 - 使用负向先行断言确保不匹配包含特殊字符的命令
        detector.addRule(Rule.builder().id("builtin-ls").name("ls")
                .pattern("^\\s*ls\\b(?!.*[;|&<>])").whitelist().riskLevel(RiskLevel.SAFE)
                .description("查看目录").build());
        detector.addRule(Rule.builder().id("builtin-cat").name("cat")
                .pattern("^\\s*cat\\b(?!.*[;|&<>])").whitelist().riskLevel(RiskLevel.SAFE)
                .description("查看文件内容").build());
        detector.addRule(Rule.builder().id("builtin-echo").name("echo/printf")
                .pattern("^\\s*echo\\b(?!.*[;|&<>])|^\\s*printf\\b(?!.*[;|&<>])").whitelist().riskLevel(RiskLevel.SAFE)
                .description("输出文本").build());
        detector.addRule(Rule.builder().id("builtin-info").name("info commands")
                .pattern("^\\s*pwd\\b(?!.*[;|&<>])|^\\s*whoami\\b(?!.*[;|&<>])|^\\s*id\\b(?!.*[;|&<>])|^\\s*date\\b(?!.*[;|&<>])|^\\s*uptime\\b(?!.*[;|&<>])")
                .whitelist().riskLevel(RiskLevel.SAFE).description("系统信息查询").build());
        detector.addRule(Rule.builder().id("builtin-process-view").name("process view")
                .pattern("^\\s*ps\\b(?!.*[;|&<>])|^\\s*top\\b(?!.*[;|&<>])").whitelist().riskLevel(RiskLevel.SAFE)
                .description("进程查看").build());
        detector.addRule(Rule.builder().id("builtin-file-view").name("file view")
                .pattern("^\\s*head\\b(?!.*[;|&<>])|^\\s*tail\\b(?!.*[;|&<>])|^\\s*less\\b(?!.*[;|&<>])|^\\s*more\\b(?!.*[;|&<>])")
                .whitelist().riskLevel(RiskLevel.SAFE).description("文件内容查看").build());
        detector.addRule(Rule.builder().id("builtin-search").name("search")
                .pattern("^\\s*grep\\b(?!.*[;|&<>])|^\\s*find\\b(?!.*[;|&<>])").whitelist().riskLevel(RiskLevel.SAFE)
                .description("搜索").build());

        return detector;
    }

    // ========== 测试用例 ==========

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

    // ========== 主程序 ==========

    public static void main(String[] args) {
        System.out.println("========================================");
        System.out.println("   Shell Detector - 手工验证测试");
        System.out.println("========================================");

        ShellDetector detector = createDefaultDetector();

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
        System.out.println("  1. 测试单个命令: java ManualTest \"rm -rf /tmp\"");
        System.out.println("  2. 交互模式:     java ManualTest interactive");
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

        CommandExtractor extractor = new CommandExtractor();
        List<String> commands = extractor.extract(command);
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

        java.util.Scanner scanner = new java.util.Scanner(System.in);
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
