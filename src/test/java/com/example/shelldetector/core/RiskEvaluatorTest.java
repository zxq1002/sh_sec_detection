package com.example.shelldetector.core;

import com.example.shelldetector.model.Rule;
import com.example.shelldetector.model.RiskLevel;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * RiskEvaluator 测试类
 * <p>
 * 测试风险评估器的功能，包括：
 * - 评估最高风险等级
 * - 判断是否应该拦截
 * </p>
 */
class RiskEvaluatorTest {

    private RiskEvaluator evaluator;

    @BeforeEach
    void setUp() {
        evaluator = new RiskEvaluator();
    }

    @Test
    void testEvaluateHighestRiskWithNullRules() {
        RiskLevel result = evaluator.evaluateHighestRisk(null);
        assertEquals(RiskLevel.SAFE, result);
    }

    @Test
    void testEvaluateHighestRiskWithEmptyRules() {
        RiskLevel result = evaluator.evaluateHighestRisk(new ArrayList<>());
        assertEquals(RiskLevel.SAFE, result);
    }

    @Test
    void testEvaluateHighestRiskSingleSafeRule() {
        List<Rule> rules = new ArrayList<>();
        rules.add(Rule.builder()
                .id("safe")
                .pattern("safe")
                .riskLevel(RiskLevel.SAFE)
                .build());

        RiskLevel result = evaluator.evaluateHighestRisk(rules);
        assertEquals(RiskLevel.SAFE, result);
    }

    @Test
    void testEvaluateHighestRiskSingleRiskRule() {
        List<Rule> rules = new ArrayList<>();
        rules.add(Rule.builder()
                .id("risk")
                .pattern("risk")
                .riskLevel(RiskLevel.RISK)
                .build());

        RiskLevel result = evaluator.evaluateHighestRisk(rules);
        assertEquals(RiskLevel.RISK, result);
    }

    @Test
    void testEvaluateHighestRiskSingleDangerRule() {
        List<Rule> rules = new ArrayList<>();
        rules.add(Rule.builder()
                .id("danger")
                .pattern("danger")
                .riskLevel(RiskLevel.DANGER)
                .build());

        RiskLevel result = evaluator.evaluateHighestRisk(rules);
        assertEquals(RiskLevel.DANGER, result);
    }

    @Test
    void testEvaluateHighestRiskMixedRules() {
        List<Rule> rules = new ArrayList<>();
        rules.add(Rule.builder()
                .id("safe")
                .pattern("safe")
                .riskLevel(RiskLevel.SAFE)
                .build());
        rules.add(Rule.builder()
                .id("risk")
                .pattern("risk")
                .riskLevel(RiskLevel.RISK)
                .build());
        rules.add(Rule.builder()
                .id("danger")
                .pattern("danger")
                .riskLevel(RiskLevel.DANGER)
                .build());

        RiskLevel result = evaluator.evaluateHighestRisk(rules);
        assertEquals(RiskLevel.DANGER, result);
    }

    @Test
    void testEvaluateHighestRiskWithNullRule() {
        List<Rule> rules = new ArrayList<>();
        rules.add(null);
        rules.add(Rule.builder()
                .id("risk")
                .pattern("risk")
                .riskLevel(RiskLevel.RISK)
                .build());

        RiskLevel result = evaluator.evaluateHighestRisk(rules);
        assertEquals(RiskLevel.RISK, result);
    }

    @Test
    void testEvaluateHighestRiskWithNullRiskLevel() {
        List<Rule> rules = new ArrayList<>();
        rules.add(Rule.builder()
                .id("null-risk")
                .pattern("null")
                .riskLevel(null)
                .build());
        rules.add(Rule.builder()
                .id("danger")
                .pattern("danger")
                .riskLevel(RiskLevel.DANGER)
                .build());

        RiskLevel result = evaluator.evaluateHighestRisk(rules);
        assertEquals(RiskLevel.DANGER, result);
    }

    @Test
    void testEvaluateHighestRiskAllNullRiskLevels() {
        List<Rule> rules = new ArrayList<>();
        rules.add(Rule.builder()
                .id("null-risk-1")
                .pattern("null1")
                .riskLevel(null)
                .build());
        rules.add(Rule.builder()
                .id("null-risk-2")
                .pattern("null2")
                .riskLevel(null)
                .build());

        RiskLevel result = evaluator.evaluateHighestRisk(rules);
        assertEquals(RiskLevel.SAFE, result);
    }

    @Test
    void testEvaluateHighestRiskOnlyNullRules() {
        List<Rule> rules = new ArrayList<>();
        rules.add(null);
        rules.add(null);

        RiskLevel result = evaluator.evaluateHighestRisk(rules);
        assertEquals(RiskLevel.SAFE, result);
    }

    @Test
    void testShouldBlockWithNullRiskLevel() {
        assertFalse(evaluator.shouldBlock(null, RiskLevel.RISK));
    }

    @Test
    void testShouldBlockWithNullThreshold() {
        assertFalse(evaluator.shouldBlock(RiskLevel.DANGER, null));
    }

    @Test
    void testShouldBlockBothNull() {
        assertFalse(evaluator.shouldBlock(null, null));
    }

    @Test
    void testShouldBlockRiskBelowThreshold() {
        assertFalse(evaluator.shouldBlock(RiskLevel.RISK, RiskLevel.DANGER));
    }

    @Test
    void testShouldBlockRiskEqualToThreshold() {
        assertTrue(evaluator.shouldBlock(RiskLevel.RISK, RiskLevel.RISK));
    }

    @Test
    void testShouldBlockRiskAboveThreshold() {
        assertTrue(evaluator.shouldBlock(RiskLevel.DANGER, RiskLevel.RISK));
    }

    @Test
    void testShouldBlockSafeWithSafeThreshold() {
        assertFalse(evaluator.shouldBlock(RiskLevel.SAFE, RiskLevel.SAFE));
    }

    @Test
    void testShouldBlockSafeWithRiskThreshold() {
        assertFalse(evaluator.shouldBlock(RiskLevel.SAFE, RiskLevel.RISK));
    }

    @Test
    void testShouldBlockDangerWithSafeThreshold() {
        assertTrue(evaluator.shouldBlock(RiskLevel.DANGER, RiskLevel.SAFE));
    }

    @Test
    void testEvaluateHighestRiskMultipleSameLevel() {
        List<Rule> rules = new ArrayList<>();
        rules.add(Rule.builder()
                .id("risk1")
                .pattern("risk1")
                .riskLevel(RiskLevel.RISK)
                .build());
        rules.add(Rule.builder()
                .id("risk2")
                .pattern("risk2")
                .riskLevel(RiskLevel.RISK)
                .build());

        RiskLevel result = evaluator.evaluateHighestRisk(rules);
        assertEquals(RiskLevel.RISK, result);
    }

    @Test
    void testEvaluateHighestRiskInOrder() {
        List<Rule> rules = new ArrayList<>();
        // 按 SAFE -> RISK -> DANGER 顺序
        rules.add(Rule.builder()
                .id("safe")
                .pattern("safe")
                .riskLevel(RiskLevel.SAFE)
                .build());
        rules.add(Rule.builder()
                .id("risk")
                .pattern("risk")
                .riskLevel(RiskLevel.RISK)
                .build());
        rules.add(Rule.builder()
                .id("danger")
                .pattern("danger")
                .riskLevel(RiskLevel.DANGER)
                .build());

        RiskLevel result = evaluator.evaluateHighestRisk(rules);
        assertEquals(RiskLevel.DANGER, result);
    }

    @Test
    void testEvaluateHighestRiskInReverseOrder() {
        List<Rule> rules = new ArrayList<>();
        // 按 DANGER -> RISK -> SAFE 顺序
        rules.add(Rule.builder()
                .id("danger")
                .pattern("danger")
                .riskLevel(RiskLevel.DANGER)
                .build());
        rules.add(Rule.builder()
                .id("risk")
                .pattern("risk")
                .riskLevel(RiskLevel.RISK)
                .build());
        rules.add(Rule.builder()
                .id("safe")
                .pattern("safe")
                .riskLevel(RiskLevel.SAFE)
                .build());

        RiskLevel result = evaluator.evaluateHighestRisk(rules);
        assertEquals(RiskLevel.DANGER, result);
    }
}
