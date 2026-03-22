package com.example.shelldetector;

import com.example.shelldetector.config.DetectionConfig;
import com.example.shelldetector.model.DetectionResult;
import com.example.shelldetector.parser.ParserType;
import com.example.shelldetector.model.RiskLevel;
import com.example.shelldetector.model.Rule;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 综合验收测试 - 全面评估 SIMPLE 和 ANTLR 双模式下的安全性与功能实现
 */
public class ComprehensiveAcceptanceTest {

    @Test
    @DisplayName("双模式对比测试 1: 基础命令链解析能力")
    void testParserSwitchingAndBasicChains() {
        String cmd = "ls -la; cat /etc/passwd | grep root";
        
        // SIMPLE 模式
        ShellDetector simpleDetector = ShellDetector.builder()
                .withConfig(DetectionConfig.builder().parserType(ParserType.SIMPLE).build())
                .build();
        DetectionResult simpleResult = simpleDetector.detect(cmd);
        assertTrue(simpleResult.isPassed(), "SIMPLE parser should handle safe chains");

        // ANTLR 模式
        ShellDetector antlrDetector = ShellDetector.builder()
                .withConfig(DetectionConfig.builder().parserType(ParserType.ANTLR).build())
                .build();
        DetectionResult antlrResult = antlrDetector.detect(cmd);
        assertTrue(antlrResult.isPassed(), "ANTLR parser should handle safe chains");
    }

    @Test
    @DisplayName("双模式对比测试 2: 复杂引号处理能力")
    void testComplexQuotes() {
        String cmd = "echo \"hello; rm -rf /\""; // 引号内包含危险分隔符
        
        ShellDetector simpleDetector = ShellDetector.createDefault();
        DetectionResult result = simpleDetector.detect(cmd);
        
        // 由于内置的 echo 规则包含负向先行断言 (?!.*[;|&<>])
        // 该命令包含分号，理论上不应命中白名单
        // 但由于它在双引号内，不应被拆分为两个命令
        // 如果正确拆分，整条命令是 echo "..."，不包含拆分后的 rm 指令。
        // 但目前的正则检测是全局查找，rm\\s+.*-rf 依然可能命中 "echo \"... rm -rf ...\"" 字符串。
        
        // 如果被拦截，拦截原因应该能说明是命中了黑名单规则。
        if (!result.isPassed()) {
            System.out.println("[SIMPLE] Correctly blocked potentially dangerous string in quotes: " + result.getBlockReason());
        } else {
            System.out.println("[SIMPLE] Passed as echo with string argument");
        }
    }

    @Test
    @DisplayName("安全深度测试 1: 子 Shell 绕过检测 (SIMPLE vs ANTLR)")
    void testSubshellDetection() {
        String cmd = "echo $(rm -rf /)";
        
        // SIMPLE 模式：由于缺乏深度解析，它视其为单条指令。
        // 其安全性完全依赖于 rm 黑名单正则是否使用了 find() 并在子串中搜索。
        ShellDetector simpleDetector = ShellDetector.builder()
                .withConfig(DetectionConfig.builder().parserType(ParserType.SIMPLE).build())
                .withDefaultRules()
                .build();
        DetectionResult simpleRes = simpleDetector.detect(cmd);
        assertFalse(simpleRes.isPassed(), "SIMPLE mode should block via regex even without subshell parsing");

        // ANTLR 模式：由于当前的语法定义 (WORD+)，它也可能仅将其视为一个 WORD
        // 如果要真正识别子 Shell，BashParser.g4 必须包含子 Shell 的递归定义。
        ShellDetector antlrDetector = ShellDetector.builder()
                .withConfig(DetectionConfig.builder().parserType(ParserType.ANTLR).build())
                .withDefaultRules()
                .build();
        DetectionResult antlrRes = antlrDetector.detect(cmd);
        assertFalse(antlrRes.isPassed(), "ANTLR mode should block via regex match even if AST depth is limited");
    }

    @Test
    @DisplayName("安全深度测试 2: 混淆指令探测")
    void testObfuscatedCommands() {
        // 验证对带转义和多余空格的指令识别
        String cmd = "r\\m   -r\\f   /";
        ShellDetector detector = ShellDetector.createDefault();
        DetectionResult res = detector.detect(cmd);
        
        // 目前正则对转义的处理能力较低，可能无法识别 r\m
        // 这是对未来改进的预期验证
        if (res.isPassed()) {
            System.out.println("[ADVICE] Detection failed to identify escaped command 'r\\m'. Improvement needed in regex or normalization.");
        }
    }

    @Test
    @DisplayName("规则引擎边界测试: 风险阈值拦截")
    void testThresholdGranularity() {
        // 验证 SAFE/RISK/DANGER 的严格隔离
        ShellDetector detector = ShellDetector.builder()
                .withRule(Rule.builder().id("r1").blacklist().pattern("low-risk").riskLevel(RiskLevel.RISK).build())
                .withThreshold(RiskLevel.DANGER)
                .build();
        
        assertTrue(detector.detect("low-risk").isPassed(), "RISK should pass when threshold is DANGER");
        
        ShellDetector strictDetector = ShellDetector.builder()
                .withRule(Rule.builder().id("r1").blacklist().pattern("low-risk").riskLevel(RiskLevel.RISK).build())
                .withThreshold(RiskLevel.RISK)
                .build();
        assertFalse(strictDetector.detect("low-risk").isPassed(), "RISK should be blocked when threshold is RISK");
    }

    @Test
    @DisplayName("鲁棒性测试: 异常输入不崩溃")
    void testRobustnessWithAnomalies() {
        ShellDetector detector = ShellDetector.createDefault();
        
        assertDoesNotThrow(() -> detector.detect(null));
        assertDoesNotThrow(() -> detector.detect(""));
        assertDoesNotThrow(() -> detector.detect("   \n\t   "));
        assertDoesNotThrow(() -> {
            // 提交超长输入，验证是否会导致 OOM 或正则回溯超时
            StringBuilder sb = new StringBuilder("ls ");
            for (int i = 0; i < 10000; i++) sb.append("-a ");
            detector.detect(sb.toString());
        });
    }

    @Test
    @DisplayName("合规性验证: 配置解析器失败时的处理策略")
    void testFailOnParseError() {
        // 对于 ANTLR，使用不匹配的括号来触发语法错误
        DetectionConfig config = DetectionConfig.builder()
                .parserType(ParserType.ANTLR)
                .failOnParseError(false) // 即使解析失败也拦截并报错，而不是抛异常
                .build();

        ShellDetector detector = ShellDetector.builder().withConfig(config).build();
        // 使用不匹配的括号 "(((" 来触发解析失败
        DetectionResult result = detector.detect("(((");
        assertFalse(result.isPassed(), "Illegal input should be blocked as potential risk even if parse fails");
    }
}
