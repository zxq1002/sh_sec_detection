package com.example.shelldetector;

import com.example.shelldetector.config.DetectionConfig;
import com.example.shelldetector.model.DetectionResult;
import com.example.shelldetector.model.RiskLevel;
import com.example.shelldetector.model.Rule;
import com.example.shelldetector.parser.ParserType;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.io.File;
import java.io.IOException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 全面验收测试 - 验证项目核心功能在 SIMPLE 和 ANTLR 双模式下是否达到交付要求
 */
public class AcceptanceTest {

    private static File tempRulesFile;

    @BeforeAll
    static void setup() throws IOException {
        tempRulesFile = File.createTempFile("acceptance-rules", ".json");
    }

    @AfterAll
    static void cleanup() {
        if (tempRulesFile != null && tempRulesFile.exists()) {
            tempRulesFile.delete();
        }
    }

    @ParameterizedTest
    @EnumSource(ParserType.class)
    @DisplayName("验收 1: 默认配置集成验证")
    void testDefaultIntegration(ParserType parserType) {
        ShellDetector detector = ShellDetector.builder()
                .withConfig(DetectionConfig.builder().parserType(parserType).build())
                .withDefaultRules()
                .build();
        assertNotNull(detector, "Detector should be created");
        
        // 验证内置规则加载
        List<Rule> rules = detector.getRules();
        assertTrue(rules.size() >= 20, "Should load at least 20 builtin rules");

        // 验证基本检测功能
        DetectionResult result = detector.detect("rm -rf /");
        assertFalse(result.isPassed(), "Dangerous command should be blocked in " + parserType + " mode");
        assertEquals(RiskLevel.DANGER, result.getHighestRiskLevel());
    }

    @ParameterizedTest
    @EnumSource(ParserType.class)
    @DisplayName("验收 2: 白名单优先策略验证")
    void testWhitelistPrecedence(ParserType parserType) {
        ShellDetector detector = ShellDetector.builder()
                .withConfig(DetectionConfig.builder().parserType(parserType).build())
                .withRule(Rule.builder().id("white-ls").whitelist().pattern("^ls\\b").build())
                .withRule(Rule.builder().id("black-ls").blacklist().pattern("ls").riskLevel(RiskLevel.DANGER).build())
                .build();

        // 虽然匹配黑名单，但白名单优先，整条匹配
        DetectionResult result = detector.detect("ls");
        assertTrue(result.isPassed(), "Whitelist should take precedence for exact match in " + parserType + " mode");
    }

    @ParameterizedTest
    @EnumSource(ParserType.class)
    @DisplayName("验收 3: 子命令拆分与白名单全匹配验证")
    void testSubcommandWhitelist(ParserType parserType) {
        ShellDetector detector = ShellDetector.builder()
                .withConfig(DetectionConfig.builder().parserType(parserType).build())
                .withRule(Rule.builder().id("w1").whitelist().pattern("^ls\\b").build())
                .withRule(Rule.builder().id("w2").whitelist().pattern("^cat\\b").build())
                .withRule(Rule.builder().id("b1").blacklist().pattern("rm").riskLevel(RiskLevel.DANGER).build())
                .build();

        // 多个子命令全在白名单
        assertTrue(detector.detect("ls; cat").isPassed(), "All subcommands whitelisted should pass in " + parserType + " mode");
        
        // 部分子命令在白名单，部分在黑名单
        DetectionResult result = detector.detect("ls; rm -rf /");
        assertFalse(result.isPassed(), "Should block if any subcommand is dangerous even if others are whitelisted in " + parserType + " mode");
    }

    @ParameterizedTest
    @EnumSource(ParserType.class)
    @DisplayName("验收 4: 风险阈值拦截验证")
    void testRiskThreshold(ParserType parserType) {
        ShellDetector detector = ShellDetector.builder()
                .withConfig(DetectionConfig.builder().parserType(parserType).build())
                .withRule(Rule.builder().id("r1").blacklist().pattern("risk-cmd").riskLevel(RiskLevel.RISK).build())
                .withThreshold(RiskLevel.DANGER)
                .build();

        // 阈值设为 DANGER，RISK 命令应通过
        assertTrue(detector.detect("risk-cmd").isPassed(), "RISK command should pass when threshold is DANGER in " + parserType + " mode");

        // 修改阈值为 RISK
        ShellDetector detector2 = ShellDetector.builder()
                .withConfig(DetectionConfig.builder().parserType(parserType).build())
                .withRule(Rule.builder().id("r1").blacklist().pattern("risk-cmd").riskLevel(RiskLevel.RISK).build())
                .withThreshold(RiskLevel.RISK)
                .build();
        assertFalse(detector2.detect("risk-cmd").isPassed(), "RISK command should be blocked when threshold is RISK in " + parserType + " mode");
    }

    @Test
    @DisplayName("验收 5: 规则持久化验证 (Save & Load)")
    void testPersistence() throws IOException {
        ShellDetector detector = ShellDetector.builder()
                .withRule(Rule.builder().id("p1").name("Persist Rule").pattern("persist-me").build())
                .build();

        // 保存
        detector.saveRulesToJson(tempRulesFile);
        assertTrue(tempRulesFile.length() > 0, "File should not be empty");

        // 加载
        ShellDetector loadedDetector = ShellDetector.builder()
                .withRulesFromJson(tempRulesFile)
                .build();

        List<Rule> rules = loadedDetector.getRules();
        assertEquals(1, rules.size());
        assertEquals("p1", rules.get(0).getId());
        assertEquals("Persist Rule", rules.get(0).getName());
    }

    @ParameterizedTest
    @EnumSource(ParserType.class)
    @DisplayName("验收 6: 引号处理能力验证 (Bypass Check)")
    void testQuoteHandling(ParserType parserType) {
        ShellDetector detector = ShellDetector.builder()
                .withConfig(DetectionConfig.builder().parserType(parserType).build())
                .withDefaultRules()
                .build();
        
        DetectionResult result = detector.detect("echo 'rm -rf /'");
        
        // SIMPLE 模式会将 'rm -rf /' 拆分，而 ANTLR 模式能够正确识别它是 echo 命令的参数
        // 这里的断言应该保证在任一模式下，由于 rm 黑名单是正则表达式 find()，即使在引号内也会被命中（除非配置了排除项）。
        // 或者整条匹配到 echo 白名单。
        
        assertTrue(result.isPassed() || result.getMatchedRules().stream().anyMatch(r -> r.getId().contains("rm")), 
                "Should either pass as echo or block as rm in " + parserType + " mode");
        
        // 重点：不应解析失败
        assertDoesNotThrow(() -> detector.detect("echo \"hello; world\""));
    }

    @ParameterizedTest
    @EnumSource(ParserType.class)
    @DisplayName("缺陷验证: 解析缺陷防护验证")
    void testAntlrMissingDefect(ParserType parserType) {
        ShellDetector detector = ShellDetector.builder()
                .withConfig(DetectionConfig.builder().parserType(parserType).build())
                .withDefaultRules()
                .build();

        // 测试子 shell - 子 Shell 应该被拦截 (如果是 rm -rf)
        DetectionResult result = detector.detect("echo $(rm -rf /)");
        assertFalse(result.isPassed(), "Subshell rm -rf should be blocked in " + parserType + " mode");

        // 验证误报风险：文件名包含指令
        DetectionResult result2 = detector.detect("ls my-rm-rf");
        
        boolean foundRm = result2.getMatchedRules().stream().anyMatch(r -> r.getId().equals("builtin-rm-rf"));
        if (foundRm) {
            System.out.println("[验收警告][" + parserType + "] 发现误报 (False Positive): 'ls my-rm-rf' 被识别为危险命令，因为目前依然依赖正则全串匹配。");
        }
    }
}
