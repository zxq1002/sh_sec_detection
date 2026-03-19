package com.example.shelldetector.core;

import com.example.shelldetector.config.DetectionConfig;
import com.example.shelldetector.model.DetectionResult;
import com.example.shelldetector.model.RiskLevel;
import com.example.shelldetector.model.Rule;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * DetectionEngine 测试类
 * <p>
 * 测试核心检测引擎的完整流程，包括：
 * - 空命令处理
 * - 整条命令白名单检测
 * - 所有子命令白名单检测
 * - 黑名单规则检测
 * - 风险评估与阈值比较
 * </p>
 */
class DetectionEngineTest {

    private DetectionEngine engine;
    private List<Rule> rules;

    @BeforeEach
    void setUp() {
        DetectionConfig config = DetectionConfig.builder()
                .threshold(RiskLevel.RISK)
                .build();
        engine = new DetectionEngine(config);
        rules = new ArrayList<>();

        // 添加测试用的白名单规则
        rules.add(Rule.builder()
                .id("test-ls")
                .name("ls")
                .whitelist()
                .pattern("^\\s*ls\\b(?!.*[;|&<>])")
                .riskLevel(RiskLevel.SAFE)
                .build());
        rules.add(Rule.builder()
                .id("test-echo")
                .name("echo")
                .whitelist()
                .pattern("^\\s*echo\\b(?!.*[;|&<>])")
                .riskLevel(RiskLevel.SAFE)
                .build());
        rules.add(Rule.builder()
                .id("test-ps")
                .name("ps")
                .whitelist()
                .pattern("^\\s*ps\\b(?!.*[;|&<>])")
                .riskLevel(RiskLevel.SAFE)
                .build());

        // 添加测试用的黑名单规则
        rules.add(Rule.builder()
                .id("test-rm-rf")
                .name("rm -rf")
                .blacklist()
                .pattern("rm\\s+.*-rf")
                .riskLevel(RiskLevel.RISK)
                .build());
        rules.add(Rule.builder()
                .id("test-file-write")
                .name("file write")
                .blacklist()
                .pattern("\\s*>\\s*[^\\s]|\\s*>>\\s*[^\\s]")
                .riskLevel(RiskLevel.RISK)
                .build());
        rules.add(Rule.builder()
                .id("test-rm-root")
                .name("rm root")
                .blacklist()
                .pattern("rm\\s+.*-rf.*\\s+/")
                .riskLevel(RiskLevel.DANGER)
                .build());
    }

    @Test
    void testNullCommandShouldPass() {
        DetectionResult result = engine.detect(null, rules);
        assertTrue(result.isPassed());
    }

    @Test
    void testEmptyCommandShouldPass() {
        DetectionResult result = engine.detect("", rules);
        assertTrue(result.isPassed());
    }

    @Test
    void testBlankCommandShouldPass() {
        DetectionResult result = engine.detect("   ", rules);
        assertTrue(result.isPassed());
    }

    @Test
    void testNullRulesShouldPass() {
        DetectionResult result = engine.detect("rm -rf /", null);
        assertTrue(result.isPassed());
    }

    @Test
    void testEmptyRulesShouldPass() {
        DetectionResult result = engine.detect("rm -rf /", new ArrayList<>());
        assertTrue(result.isPassed());
    }

    @Test
    void testSimpleWhitelistCommandShouldPass() {
        DetectionResult result = engine.detect("ls -la", rules);
        assertTrue(result.isPassed());
    }

    @Test
    void testWhitelistCommandWithSpecialCharsShouldNotPassWhitelist() {
        // 白名单规则有 (?!.*[;|&<>])，所以包含特殊字符的命令不会匹配白名单
        DetectionResult result = engine.detect("ls -la; echo hello", rules);
        // 虽然不匹配白名单，但也没有匹配黑名单，所以会通过
        assertTrue(result.isPassed());
    }

    @Test
    void testBlacklistCommandShouldBeBlocked() {
        DetectionResult result = engine.detect("rm -rf /tmp", rules);
        assertFalse(result.isPassed());
        assertEquals(RiskLevel.RISK, result.getHighestRiskLevel());
        assertEquals(1, result.getMatchedRules().size());
    }

    @Test
    void testDangerLevelCommandShouldBeBlocked() {
        DetectionResult result = engine.detect("rm -rf /", rules);
        assertFalse(result.isPassed());
        assertEquals(RiskLevel.DANGER, result.getHighestRiskLevel());
    }

    @Test
    void testPipeCommandWithBlacklistShouldBeBlocked() {
        DetectionResult result = engine.detect("ps -ef | rm -rf xxx.sh", rules);
        assertFalse(result.isPassed());
    }

    @Test
    void testEchoWithWriteRedirectionShouldBeBlocked() {
        DetectionResult result = engine.detect("echo '123' > 123.sh", rules);
        assertFalse(result.isPassed());
    }

    @Test
    void testEchoWithAppendRedirectionShouldBeBlocked() {
        DetectionResult result = engine.detect("echo '123' >> 123.sh", rules);
        assertFalse(result.isPassed());
    }

    @Test
    void testMultipleCommandsWithBlacklistShouldBeBlocked() {
        DetectionResult result = engine.detect("ls -la; rm -rf /tmp", rules);
        assertFalse(result.isPassed());
    }

    @Test
    void testAllSubcommandsWhitelistedShouldPass() {
        // 创建两条都在白名单的命令
        List<Rule> whitelistOnly = new ArrayList<>();
        whitelistOnly.add(Rule.builder()
                .id("w1")
                .whitelist()
                .pattern("^\\s*ls\\b")
                .build());
        whitelistOnly.add(Rule.builder()
                .id("w2")
                .whitelist()
                .pattern("^\\s*echo\\b")
                .build());

        DetectionResult result = engine.detect("ls -la; echo hello", whitelistOnly);
        assertTrue(result.isPassed());
    }

    @Test
    void testSomeSubcommandsNotWhitelistedShouldCheckBlacklist() {
        List<Rule> testRules = new ArrayList<>();
        testRules.add(Rule.builder()
                .id("w-ls")
                .whitelist()
                .pattern("^\\s*ls\\b")
                .build());
        testRules.add(Rule.builder()
                .id("b-danger")
                .blacklist()
                .pattern("danger")
                .riskLevel(RiskLevel.RISK)
                .build());

        // "ls" 在白名单，"danger" 不在白名单但匹配黑名单
        DetectionResult result = engine.detect("ls -la; danger cmd", testRules);
        assertFalse(result.isPassed());
    }

    @Test
    void testRiskLevelBelowThresholdShouldPass() {
        DetectionConfig config = DetectionConfig.builder()
                .threshold(RiskLevel.DANGER)
                .build();
        DetectionEngine engineWithHigherThreshold = new DetectionEngine(config);

        // RISK 级别低于 DANGER 阈值，应该通过
        DetectionResult result = engineWithHigherThreshold.detect("rm -rf /tmp", rules);
        assertTrue(result.isPassed());
    }

    @Test
    void testRiskLevelEqualToThresholdShouldBeBlocked() {
        DetectionConfig config = DetectionConfig.builder()
                .threshold(RiskLevel.RISK)
                .build();
        DetectionEngine engineWithRiskThreshold = new DetectionEngine(config);

        DetectionResult result = engineWithRiskThreshold.detect("rm -rf /tmp", rules);
        assertFalse(result.isPassed());
    }

    @Test
    void testHighestRiskLevelIsCorrect() {
        List<Rule> multipleRisks = new ArrayList<>();
        multipleRisks.add(Rule.builder()
                .id("risk1")
                .blacklist()
                .pattern("risk1")
                .riskLevel(RiskLevel.RISK)
                .build());
        multipleRisks.add(Rule.builder()
                .id("danger1")
                .blacklist()
                .pattern("danger1")
                .riskLevel(RiskLevel.DANGER)
                .build());
        multipleRisks.add(Rule.builder()
                .id("risk2")
                .blacklist()
                .pattern("risk2")
                .riskLevel(RiskLevel.RISK)
                .build());

        DetectionResult result = engine.detect("risk1 danger1 risk2", multipleRisks);
        assertEquals(RiskLevel.DANGER, result.getHighestRiskLevel());
    }

    @Test
    void testNoMatchedRulesShouldPass() {
        DetectionResult result = engine.detect("unknown command", rules);
        assertTrue(result.isPassed());
        assertEquals(RiskLevel.SAFE, result.getHighestRiskLevel());
        assertTrue(result.getMatchedRules().isEmpty());
    }
}
