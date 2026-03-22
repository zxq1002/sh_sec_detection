package com.example.shelldetector;

import com.example.shelldetector.config.DetectionConfig;
import com.example.shelldetector.core.DetectionEngine;
import com.example.shelldetector.model.DetectionResult;
import com.example.shelldetector.model.RiskLevel;
import com.example.shelldetector.model.Rule;
import com.example.shelldetector.parser.ParserType;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 解析器集成测试 - 验证两种解析器在检测引擎中的集成
 * <p>
 * 测试重点：
 * <ul>
 *     <li>默认使用 SIMPLE 解析器（向后兼容）</li>
 *     <li>可配置使用 ANTLR 解析器</li>
 *     <li>两种解析器都能正常工作</li>
 * </ul>
 * </p>
 */
class ParserIntegrationTest {

    @Test
    void testDefaultUsesSimpleParser() {
        DetectionConfig config = DetectionConfig.builder().build();
        assertEquals(ParserType.SIMPLE, config.getParserType(), "Default parser should be SIMPLE");
    }

    @Test
    void testCanConfigureAntlrParser() {
        DetectionConfig config = DetectionConfig.builder()
                .parserType(ParserType.ANTLR)
                .build();
        assertEquals(ParserType.ANTLR, config.getParserType());
    }

    @Test
    void testDetectionEngineWithSimpleParser() {
        DetectionConfig config = DetectionConfig.builder()
                .parserType(ParserType.SIMPLE)
                .threshold(RiskLevel.RISK)
                .build();
        DetectionEngine engine = new DetectionEngine(config);

        Rule rule = Rule.builder()
                .id("test-rm")
                .pattern("rm\\s+-rf")
                .blacklist()
                .riskLevel(RiskLevel.RISK)
                .build();
        List<Rule> rules = Arrays.asList(rule);

        DetectionResult result = engine.detect("rm -rf /tmp", rules);
        assertFalse(result.isPassed());
    }

    @Test
    void testDetectionEngineWithAntlrParser() {
        DetectionConfig config = DetectionConfig.builder()
                .parserType(ParserType.ANTLR)
                .threshold(RiskLevel.RISK)
                .build();
        DetectionEngine engine = new DetectionEngine(config);

        Rule rule = Rule.builder()
                .id("test-rm")
                .pattern("rm\\s+-rf")
                .blacklist()
                .riskLevel(RiskLevel.RISK)
                .build();
        List<Rule> rules = Arrays.asList(rule);

        DetectionResult result = engine.detect("rm -rf /tmp", rules);
        assertFalse(result.isPassed());
    }

    @Test
    void testShellDetectorWithSimpleParser() {
        ShellDetector detector = ShellDetector.builder()
                .withRule(Rule.builder()
                        .id("test-echo")
                        .pattern("^\\s*echo\\b")
                        .whitelist()
                        .build())
                .withRule(Rule.builder()
                        .id("test-rm")
                        .pattern("rm\\s+-rf")
                        .blacklist()
                        .riskLevel(RiskLevel.RISK)
                        .build())
                .withParserType(ParserType.SIMPLE)
                .withThreshold(RiskLevel.RISK)
                .build();

        DetectionResult safeResult = detector.detect("echo hello");
        assertTrue(safeResult.isPassed());

        DetectionResult dangerResult = detector.detect("rm -rf /tmp");
        assertFalse(dangerResult.isPassed());
    }

    @Test
    void testShellDetectorWithAntlrParser() {
        ShellDetector detector = ShellDetector.builder()
                .withRule(Rule.builder()
                        .id("test-echo")
                        .pattern("^\\s*echo\\b")
                        .whitelist()
                        .build())
                .withRule(Rule.builder()
                        .id("test-rm")
                        .pattern("rm\\s+-rf")
                        .blacklist()
                        .riskLevel(RiskLevel.RISK)
                        .build())
                .withParserType(ParserType.ANTLR)
                .withThreshold(RiskLevel.RISK)
                .build();

        DetectionResult safeResult = detector.detect("echo hello");
        assertTrue(safeResult.isPassed());

        DetectionResult dangerResult = detector.detect("rm -rf /tmp");
        assertFalse(dangerResult.isPassed());
    }

    @Test
    void testBackwardCompatibilityNoParserConfig() {
        // 不设置 parserType，使用默认值
        ShellDetector detector = ShellDetector.builder()
                .withRule(Rule.builder()
                        .id("test-rm")
                        .pattern("rm\\s+-rf")
                        .blacklist()
                        .riskLevel(RiskLevel.RISK)
                        .build())
                .withThreshold(RiskLevel.RISK)
                .build();

        DetectionResult result = detector.detect("rm -rf /tmp");
        assertFalse(result.isPassed());
    }
}
